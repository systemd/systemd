# SPDX-License-Identifier: LGPL-2.1+

project('systemd', 'c',
        version : '243',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu99',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
        ],
        meson_version : '>= 0.46',
       )

libsystemd_version = '0.27.0'
libudev_version = '1.6.15'

# We need the same data in two different formats, ugh!
# Also, for hysterical reasons, we use different variable
# names, sometimes. Not all variables are included in every
# set. Ugh, ugh, ugh!
conf = configuration_data()
conf.set('PROJECT_VERSION',        meson.project_version())

substs = configuration_data()
substs.set('PROJECT_URL',          'https://www.freedesktop.org/wiki/Software/systemd')
substs.set('PROJECT_VERSION',      meson.project_version())

# This is to be used instead of meson.source_root(), as the latter will return
# the wrong result when systemd is being built as a meson subproject
project_source_root = meson.current_source_dir()
relative_source_path = run_command('realpath',
                                   '--relative-to=@0@'.format(meson.current_build_dir()),
                                   project_source_root).stdout().strip()
conf.set_quoted('RELATIVE_SOURCE_PATH', relative_source_path)

want_ossfuzz = get_option('oss-fuzz')
want_libfuzzer = get_option('llvm-fuzz')
want_fuzzbuzz = get_option('fuzzbuzz')
if want_ossfuzz + want_libfuzzer + want_fuzzbuzz > 1
        error('only one of oss-fuzz, llvm-fuzz or fuzzbuzz can be specified')
endif

skip_deps = want_ossfuzz or want_libfuzzer
fuzzer_build = want_ossfuzz or want_libfuzzer or want_fuzzbuzz

#####################################################################

# Try to install the git pre-commit hook
git_hook = run_command(join_paths(project_source_root, 'tools/add-git-hook.sh'))
if git_hook.returncode() == 0
        message(git_hook.stdout().strip())
endif

#####################################################################

if get_option('split-usr') == 'auto'
        split_usr = run_command('test', '-L', '/bin').returncode() != 0
else
        split_usr = get_option('split-usr') == 'true'
endif
conf.set10('HAVE_SPLIT_USR', split_usr,
           description : '/usr/bin and /bin directories are separate')

if get_option('split-bin') == 'auto'
        split_bin = run_command('test', '-L', '/usr/sbin').returncode() != 0
else
        split_bin = get_option('split-bin') == 'true'
endif
conf.set10('HAVE_SPLIT_BIN', split_bin,
           description : 'bin and sbin directories are separate')

rootprefixdir = get_option('rootprefix')
# Unusual rootprefixdir values are used by some distros
# (see https://github.com/systemd/systemd/pull/7461).
rootprefix_default = split_usr ? '/' : '/usr'
if rootprefixdir == ''
        rootprefixdir = rootprefix_default
endif
rootprefixdir_noslash = rootprefixdir == '/' ? '' : rootprefixdir

sysvinit_path = get_option('sysvinit-path')
sysvrcnd_path = get_option('sysvrcnd-path')
conf.set10('HAVE_SYSV_COMPAT', sysvinit_path != '' and sysvrcnd_path != '',
           description : 'SysV init scripts and rcN.d links are supported')

conf.set10('BUMP_PROC_SYS_FS_FILE_MAX', get_option('bump-proc-sys-fs-file-max'))
conf.set10('BUMP_PROC_SYS_FS_NR_OPEN',  get_option('bump-proc-sys-fs-nr-open'))
conf.set('HIGH_RLIMIT_NOFILE',          512*1024)

# join_paths ignores the preceding arguments if an absolute component is
# encountered, so this should canonicalize various paths when they are
# absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
bindir = join_paths(prefixdir, get_option('bindir'))
libdir = join_paths(prefixdir, get_option('libdir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
datadir = join_paths(prefixdir, get_option('datadir'))
localstatedir = join_paths('/', get_option('localstatedir'))

rootbindir = join_paths(rootprefixdir, 'bin')
rootsbindir = join_paths(rootprefixdir, split_bin ? 'sbin' : 'bin')
rootlibexecdir = join_paths(rootprefixdir, 'lib/systemd')

rootlibdir = get_option('rootlibdir')
if rootlibdir == ''
        rootlibdir = join_paths(rootprefixdir, libdir.split('/')[-1])
endif

# Dirs of external packages
pkgconfigdatadir = get_option('pkgconfigdatadir') == '' ? join_paths(datadir, 'pkgconfig') : get_option('pkgconfigdatadir')
pkgconfiglibdir = get_option('pkgconfiglibdir') == '' ? join_paths(libdir, 'pkgconfig') : get_option('pkgconfiglibdir')
polkitpolicydir = join_paths(datadir, 'polkit-1/actions')
polkitrulesdir = join_paths(datadir, 'polkit-1/rules.d')
polkitpkladir = join_paths(localstatedir, 'lib/polkit-1/localauthority/10-vendor.d')
xinitrcdir = join_paths(sysconfdir, 'X11/xinit/xinitrc.d')
rpmmacrosdir = get_option('rpmmacrosdir')
if rpmmacrosdir != 'no'
        rpmmacrosdir = join_paths(prefixdir, rpmmacrosdir)
endif
modprobedir = join_paths(rootprefixdir, 'lib/modprobe.d')

# Our own paths
pkgdatadir = join_paths(datadir, 'systemd')
environmentdir = join_paths(prefixdir, 'lib/environment.d')
pkgsysconfdir = join_paths(sysconfdir, 'systemd')
userunitdir = join_paths(prefixdir, 'lib/systemd/user')
userpresetdir = join_paths(prefixdir, 'lib/systemd/user-preset')
tmpfilesdir = join_paths(prefixdir, 'lib/tmpfiles.d')
sysusersdir = join_paths(prefixdir, 'lib/sysusers.d')
sysctldir = join_paths(prefixdir, 'lib/sysctl.d')
binfmtdir = join_paths(prefixdir, 'lib/binfmt.d')
modulesloaddir = join_paths(prefixdir, 'lib/modules-load.d')
networkdir = join_paths(rootprefixdir, 'lib/systemd/network')
pkgincludedir = join_paths(includedir, 'systemd')
systemgeneratordir = join_paths(rootlibexecdir, 'system-generators')
usergeneratordir = join_paths(prefixdir, 'lib/systemd/user-generators')
systemenvgeneratordir = join_paths(prefixdir, 'lib/systemd/system-environment-generators')
userenvgeneratordir = join_paths(prefixdir, 'lib/systemd/user-environment-generators')
systemshutdowndir = join_paths(rootlibexecdir, 'system-shutdown')
systemsleepdir = join_paths(rootlibexecdir, 'system-sleep')
systemunitdir = join_paths(rootprefixdir, 'lib/systemd/system')
systempresetdir = join_paths(rootprefixdir, 'lib/systemd/system-preset')
udevlibexecdir = join_paths(rootprefixdir, 'lib/udev')
udevrulesdir = join_paths(udevlibexecdir, 'rules.d')
udevhwdbdir = join_paths(udevlibexecdir, 'hwdb.d')
catalogdir = join_paths(prefixdir, 'lib/systemd/catalog')
kernelinstalldir = join_paths(prefixdir, 'lib/kernel/install.d')
factorydir = join_paths(datadir, 'factory')
bootlibdir = join_paths(prefixdir, 'lib/systemd/boot/efi')
testsdir = join_paths(prefixdir, 'lib/systemd/tests')
systemdstatedir = join_paths(localstatedir, 'lib/systemd')
catalogstatedir = join_paths(systemdstatedir, 'catalog')
randomseeddir = join_paths(localstatedir, 'lib/systemd')
profiledir = join_paths(rootlibexecdir, 'portable', 'profile')
ntpservicelistdir = join_paths(rootprefixdir, 'lib/systemd/ntp-units.d')

docdir = get_option('docdir')
if docdir == ''
        docdir = join_paths(datadir, 'doc/systemd')
endif

dbuspolicydir = get_option('dbuspolicydir')
if dbuspolicydir == ''
        dbuspolicydir = join_paths(datadir, 'dbus-1/system.d')
endif

dbussessionservicedir = get_option('dbussessionservicedir')
if dbussessionservicedir == ''
        dbussessionservicedir = join_paths(datadir, 'dbus-1/services')
endif

dbussystemservicedir = get_option('dbussystemservicedir')
if dbussystemservicedir == ''
        dbussystemservicedir = join_paths(datadir, 'dbus-1/system-services')
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = join_paths(rootlibdir, 'security')
endif

pamconfdir = get_option('pamconfdir')
if pamconfdir == ''
        pamconfdir = join_paths(sysconfdir, 'pam.d')
endif

memory_accounting_default = get_option('memory-accounting-default')
status_unit_format_default = get_option('status-unit-format-default')

conf.set_quoted('PKGSYSCONFDIR',                              pkgsysconfdir)
conf.set_quoted('SYSTEM_CONFIG_UNIT_PATH',                    join_paths(pkgsysconfdir, 'system'))
conf.set_quoted('SYSTEM_DATA_UNIT_PATH',                      systemunitdir)
conf.set_quoted('SYSTEM_SYSVINIT_PATH',                       sysvinit_path)
conf.set_quoted('SYSTEM_SYSVRCND_PATH',                       sysvrcnd_path)
conf.set_quoted('RC_LOCAL_SCRIPT_PATH_START',                 get_option('rc-local'))

conf.set('ANSI_OK_COLOR',                                     'ANSI_' + get_option('ok-color').underscorify().to_upper())

conf.set_quoted('USER_CONFIG_UNIT_PATH',                      join_paths(pkgsysconfdir, 'user'))
conf.set_quoted('USER_DATA_UNIT_PATH',                        userunitdir)
conf.set_quoted('CERTIFICATE_ROOT',                           get_option('certificate-root'))
conf.set_quoted('CATALOG_DATABASE',                           join_paths(catalogstatedir, 'database'))
conf.set_quoted('SYSTEMD_CGROUP_AGENT_PATH',                  join_paths(rootlibexecdir, 'systemd-cgroups-agent'))
conf.set_quoted('SYSTEMD_BINARY_PATH',                        join_paths(rootlibexecdir, 'systemd'))
conf.set_quoted('SYSTEMD_FSCK_PATH',                          join_paths(rootlibexecdir, 'systemd-fsck'))
conf.set_quoted('SYSTEMD_MAKEFS_PATH',                        join_paths(rootlibexecdir, 'systemd-makefs'))
conf.set_quoted('SYSTEMD_GROWFS_PATH',                        join_paths(rootlibexecdir, 'systemd-growfs'))
conf.set_quoted('SYSTEMD_SHUTDOWN_BINARY_PATH',               join_paths(rootlibexecdir, 'systemd-shutdown'))
conf.set_quoted('SYSTEMD_SLEEP_BINARY_PATH',                  join_paths(rootlibexecdir, 'systemd-sleep'))
conf.set_quoted('SYSTEMCTL_BINARY_PATH',                      join_paths(rootbindir, 'systemctl'))
conf.set_quoted('SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH', join_paths(rootbindir, 'systemd-tty-ask-password-agent'))
conf.set_quoted('SYSTEMD_STDIO_BRIDGE_BINARY_PATH',           join_paths(bindir, 'systemd-stdio-bridge'))
conf.set_quoted('ROOTPREFIX',                                 rootprefixdir)
conf.set_quoted('RANDOM_SEED_DIR',                            randomseeddir)
conf.set_quoted('RANDOM_SEED',                                join_paths(randomseeddir, 'random-seed'))
conf.set_quoted('SYSTEMD_CRYPTSETUP_PATH',                    join_paths(rootlibexecdir, 'systemd-cryptsetup'))
conf.set_quoted('SYSTEM_GENERATOR_PATH',                      systemgeneratordir)
conf.set_quoted('USER_GENERATOR_PATH',                        usergeneratordir)
conf.set_quoted('SYSTEM_ENV_GENERATOR_PATH',                  systemenvgeneratordir)
conf.set_quoted('USER_ENV_GENERATOR_PATH',                    userenvgeneratordir)
conf.set_quoted('SYSTEM_SHUTDOWN_PATH',                       systemshutdowndir)
conf.set_quoted('SYSTEM_SLEEP_PATH',                          systemsleepdir)
conf.set_quoted('SYSTEMD_KBD_MODEL_MAP',                      join_paths(pkgdatadir, 'kbd-model-map'))
conf.set_quoted('SYSTEMD_LANGUAGE_FALLBACK_MAP',              join_paths(pkgdatadir, 'language-fallback-map'))
conf.set_quoted('SYSTEMD_TEST_DATA',                          join_paths(testsdir, 'testdata'))
conf.set_quoted('SYSTEMD_CATALOG_DIR',                        catalogdir)
conf.set_quoted('UDEVLIBEXECDIR',                             udevlibexecdir)
conf.set_quoted('POLKIT_AGENT_BINARY_PATH',                   join_paths(bindir, 'pkttyagent'))
conf.set_quoted('LIBDIR',                                     libdir)
conf.set_quoted('ROOTLIBDIR',                                 rootlibdir)
conf.set_quoted('ROOTLIBEXECDIR',                             rootlibexecdir)
conf.set_quoted('BOOTLIBDIR',                                 bootlibdir)
conf.set_quoted('SYSTEMD_PULL_PATH',                          join_paths(rootlibexecdir, 'systemd-pull'))
conf.set_quoted('SYSTEMD_IMPORT_PATH',                        join_paths(rootlibexecdir, 'systemd-import'))
conf.set_quoted('SYSTEMD_IMPORT_FS_PATH',                     join_paths(rootlibexecdir, 'systemd-import-fs'))
conf.set_quoted('SYSTEMD_EXPORT_PATH',                        join_paths(rootlibexecdir, 'systemd-export'))
conf.set_quoted('VENDOR_KEYRING_PATH',                        join_paths(rootlibexecdir, 'import-pubring.gpg'))
conf.set_quoted('USER_KEYRING_PATH',                          join_paths(pkgsysconfdir, 'import-pubring.gpg'))
conf.set_quoted('DOCUMENT_ROOT',                              join_paths(pkgdatadir, 'gatewayd'))
conf.set10('MEMORY_ACCOUNTING_DEFAULT',                       memory_accounting_default)
conf.set_quoted('MEMORY_ACCOUNTING_DEFAULT_YES_NO',           memory_accounting_default ? 'yes' : 'no')
conf.set('STATUS_UNIT_FORMAT_DEFAULT',                        'STATUS_UNIT_FORMAT_' + status_unit_format_default.to_upper())

substs.set('prefix',                                          prefixdir)
substs.set('rootprefix',                                      rootprefixdir)
substs.set('rootprefix_noslash',                              rootprefixdir_noslash)
substs.set('exec_prefix',                                     prefixdir)
substs.set('libdir',                                          libdir)
substs.set('rootlibdir',                                      rootlibdir)
substs.set('includedir',                                      includedir)
substs.set('sysconfdir',                                      sysconfdir)
substs.set('bindir',                                          bindir)
substs.set('rootbindir',                                      rootbindir)
substs.set('rootlibexecdir',                                  rootlibexecdir)
substs.set('systemunitdir',                                   systemunitdir)
substs.set('userunitdir',                                     userunitdir)
substs.set('systempresetdir',                                 systempresetdir)
substs.set('userpresetdir',                                   userpresetdir)
substs.set('udevhwdbdir',                                     udevhwdbdir)
substs.set('udevrulesdir',                                    udevrulesdir)
substs.set('udevlibexecdir',                                  udevlibexecdir)
substs.set('environmentdir',                                  environmentdir)
substs.set('catalogdir',                                      catalogdir)
substs.set('tmpfilesdir',                                     tmpfilesdir)
substs.set('sysusersdir',                                     sysusersdir)
substs.set('sysctldir',                                       sysctldir)
substs.set('binfmtdir',                                       binfmtdir)
substs.set('modulesloaddir',                                  modulesloaddir)
substs.set('modprobedir',                                     modprobedir)
substs.set('systemgeneratordir',                              systemgeneratordir)
substs.set('usergeneratordir',                                usergeneratordir)
substs.set('systemenvgeneratordir',                           systemenvgeneratordir)
substs.set('userenvgeneratordir',                             userenvgeneratordir)
substs.set('systemshutdowndir',                               systemshutdowndir)
substs.set('systemsleepdir',                                  systemsleepdir)
substs.set('CERTIFICATEROOT',                                 get_option('certificate-root'))
substs.set('SYSTEMCTL',                                       join_paths(rootbindir, 'systemctl'))
substs.set('RANDOM_SEED',                                     join_paths(randomseeddir, 'random-seed'))
substs.set('SYSTEM_SYSVINIT_PATH',                            sysvinit_path)
substs.set('SYSTEM_SYSVRCND_PATH',                            sysvrcnd_path)
substs.set('RC_LOCAL_SCRIPT_PATH_START',                      get_option('rc-local'))
substs.set('MEMORY_ACCOUNTING_DEFAULT',                       memory_accounting_default ? 'yes' : 'no')
substs.set('STATUS_UNIT_FORMAT_DEFAULT',                      status_unit_format_default)
substs.set('HIGH_RLIMIT_NOFILE',                              conf.get('HIGH_RLIMIT_NOFILE'))
substs.set('BUILD_ROOT',                                      meson.current_build_dir())

#####################################################################

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')
check_compilation_sh = find_program('tools/meson-check-compilation.sh')
meson_build_sh = find_program('tools/meson-build.sh')

want_tests = get_option('tests')
slow_tests = want_tests != 'false' and get_option('slow-tests')
install_tests = get_option('install-tests')

if add_languages('cpp', required : fuzzer_build)
        #  Used only for tests
        cxx_cmd = ' '.join(meson.get_compiler('cpp').cmd_array())
else
        cxx_cmd = ''
endif

if want_libfuzzer
        fuzzing_engine = meson.get_compiler('cpp').find_library('Fuzzer', required : false)
        if fuzzing_engine.found()
                add_project_arguments('-fsanitize-coverage=trace-pc-guard,trace-cmp', language : 'c')
        elif cc.has_argument('-fsanitize=fuzzer-no-link')
                add_project_arguments('-fsanitize=fuzzer-no-link', language : 'c')
        else
                error('Looks like neither libFuzzer nor -fsanitize=fuzzer-no-link is supported')
        endif
elif want_ossfuzz
        fuzzing_engine = meson.get_compiler('cpp').find_library('FuzzingEngine')
elif want_fuzzbuzz
        fuzzing_engine = meson.get_compiler('cpp').find_library(get_option('fuzzbuzz-engine'), dirs: get_option('fuzzbuzz-engine-dir'))
endif

possible_cc_flags = [
        '-Wextra',
        '-Werror=undef',
        '-Wlogical-op',
        '-Wmissing-include-dirs',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Winit-self',
        '-Wfloat-equal',
        '-Wsuggest-attribute=noreturn',
        '-Werror=missing-prototypes',
        '-Werror=implicit-function-declaration',
        '-Werror=missing-declarations',
        '-Werror=return-type',
        '-Werror=incompatible-pointer-types',
        '-Werror=format=2',
        '-Wstrict-prototypes',
        '-Wredundant-decls',
        '-Wmissing-noreturn',
        '-Wimplicit-fallthrough=5',
        '-Wshadow',
        '-Wendif-labels',
        '-Wstrict-aliasing=2',
        '-Wwrite-strings',
        '-Werror=overflow',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Wdate-time',
        '-Wnested-externs',

        # negative arguments are correctly detected starting with meson 0.46.
        '-Wno-unused-parameter',
        '-Wno-missing-field-initializers',
        '-Wno-unused-result',
        '-Wno-format-signedness',
        '-Wno-error=#warnings',  # clang
        '-Wno-string-plus-int',  # clang

        # work-around for gcc 7.1 turning this on on its own.
        '-Wno-error=nonnull',

        # Disable -Wmaybe-uninitialized, since it's noisy on gcc 8 with
        # optimizations enabled, producing essentially false positives.
        '-Wno-maybe-uninitialized',

        '-ffast-math',
        '-fno-common',
        '-fdiagnostics-show-option',
        '-fno-strict-aliasing',
        '-fvisibility=hidden',
        '-fstack-protector',
        '-fstack-protector-strong',
        '--param=ssp-buffer-size=4',
]

# --as-needed and --no-undefined are provided by meson by default,
# run mesonconf to see what is enabled
possible_link_flags = [
        '-Wl,-z,relro',
        '-Wl,-z,now',
]

if cc.get_id() == 'clang'
        possible_cc_flags += [
                '-Wno-typedef-redefinition',
                '-Wno-gnu-variable-sized-type-not-at-end',
        ]
endif

if get_option('buildtype') != 'debug'
        possible_cc_flags += [
                '-ffunction-sections',
                '-fdata-sections',
        ]

        possible_link_flags += '-Wl,--gc-sections'
endif

if get_option('b_ndebug') == 'true'
        # With asserts disabled with get a bunch of warnings about variables which
        # are used only in the asserts. This is not useful at all, so let's just silence
        # those warnings.
        possible_cc_flags += [
                '-Wno-unused-variable',
                '-Wno-unused-but-set-variable',
        ]
endif

add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')
add_project_link_arguments(cc.get_supported_link_arguments(possible_link_flags), language : 'c')

if cc.compiles('''
   #include <time.h>
   #include <inttypes.h>
   typedef uint64_t usec_t;
   usec_t now(clockid_t clock);
   int main(void) {
           struct timespec now;
           return 0;
   }
''', args: '-Werror=shadow', name : '-Werror=shadow with local shadowing')
        add_project_arguments('-Werror=shadow', language : 'c')
endif

cpp = ' '.join(cc.cmd_array()) + ' -E'

has_wstringop_truncation = cc.has_argument('-Wstringop-truncation')

#####################################################################
# compilation result tests

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)
conf.set10('HAVE_WSTRINGOP_TRUNCATION', has_wstringop_truncation)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))

decl_headers = '''
#include <uchar.h>
#include <sys/stat.h>
'''

foreach decl : ['char16_t',
                'char32_t',
                'struct statx',
               ]

        # We get -1 if the size cannot be determined
        have = cc.sizeof(decl, prefix : decl_headers, args : '-D_GNU_SOURCE') > 0

        if decl == 'struct statx'
                if have
                        want_linux_stat_h = false
                else
                        have = cc.sizeof(decl,
                                         prefix : decl_headers + '#include <linux/stat.h>',
                                         args : '-D_GNU_SOURCE') > 0
                        want_linux_stat_h = have
                endif
        endif

        conf.set10('HAVE_' + decl.underscorify().to_upper(), have)
endforeach

conf.set10('WANT_LINUX_STAT_H', want_linux_stat_h)

foreach ident : ['secure_getenv', '__secure_getenv']
        conf.set10('HAVE_' + ident.to_upper(), cc.has_function(ident))
endforeach

foreach ident : [
        ['memfd_create',      '''#include <sys/mman.h>'''],
        ['gettid',            '''#include <sys/types.h>
                                 #include <unistd.h>'''],
        ['pivot_root',        '''#include <stdlib.h>
                                 #include <unistd.h>'''],     # no known header declares pivot_root
        ['name_to_handle_at', '''#include <sys/types.h>
                                 #include <sys/stat.h>
                                 #include <fcntl.h>'''],
        ['setns',             '''#include <sched.h>'''],
        ['renameat2',         '''#include <stdio.h>
                                 #include <fcntl.h>'''],
        ['kcmp',              '''#include <linux/kcmp.h>'''],
        ['keyctl',            '''#include <sys/types.h>
                                 #include <keyutils.h>'''],
        ['copy_file_range',   '''#include <sys/syscall.h>
                                 #include <unistd.h>'''],
        ['bpf',               '''#include <sys/syscall.h>
                                 #include <unistd.h>'''],
        ['statx',             '''#include <sys/types.h>
                                 #include <sys/stat.h>
                                 #include <unistd.h>'''],
        ['explicit_bzero' ,   '''#include <string.h>'''],
        ['reallocarray',      '''#include <malloc.h>'''],
        ['set_mempolicy',     '''#include <stdlib.h>
                                 #include <unistd.h>'''],
        ['get_mempolicy',     '''#include <stdlib.h>
                                 #include <unistd.h>'''],
]

        have = cc.has_function(ident[0], prefix : ident[1], args : '-D_GNU_SOURCE')
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''', args : '-D_GNU_SOURCE')
        conf.set10('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_GETRANDOM', true)
else
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', false)
        conf.set10('HAVE_GETRANDOM', have)
endif

#####################################################################

vcs_tagger = [project_source_root + '/tools/meson-vcs-tag.sh',
              project_source_root,
              get_option('version-tag'),
              meson.project_version()]

version_h = vcs_tag(
        input : 'src/version/version.h.in',
        output : 'version.h',
        command: vcs_tagger)

versiondep = declare_dependency(sources: version_h)

sed = find_program('sed')
awk = find_program('awk')
m4 = find_program('m4')
stat = find_program('stat')
git = find_program('git', required : false)
env = find_program('env')
perl = find_program('perl', required : false)

meson_make_symlink = project_source_root + '/tools/meson-make-symlink.sh'
mkdir_p = 'mkdir -p $DESTDIR/@0@'
test_efi_create_disk_sh = find_program('test/test-efi-create-disk.sh')
splash_bmp = files('test/splash.bmp')

# if -Dxxx-path option is found, use that. Otherwise, check in $PATH,
# /usr/sbin, /sbin, and fall back to the default from middle column.
progs = [['quotaon',    '/usr/sbin/quotaon'    ],
         ['quotacheck', '/usr/sbin/quotacheck' ],
         ['kmod',       '/usr/bin/kmod'        ],
         ['kexec',      '/usr/sbin/kexec'      ],
         ['sulogin',    '/usr/sbin/sulogin'    ],
         ['mount',      '/usr/bin/mount',      'MOUNT_PATH'],
         ['umount',     '/usr/bin/umount',     'UMOUNT_PATH'],
         ['loadkeys',   '/usr/bin/loadkeys',   'KBD_LOADKEYS'],
         ['setfont',    '/usr/bin/setfont',    'KBD_SETFONT'],
         ['nologin',    '/usr/sbin/nologin',   ],
        ]
foreach prog : progs
        path = get_option(prog[0] + '-path')
        if path != ''
                message('Using @1@ for @0@'.format(prog[0], path))
        else
                exe = find_program(prog[0],
                                   '/usr/sbin/' + prog[0],
                                   '/sbin/' + prog[0],
                                   required: false)
                path = exe.found() ? exe.path() : prog[1]
        endif
        name = prog.length() > 2 ? prog[2] : prog[0].to_upper()
        conf.set_quoted(name, path)
        substs.set(name, path)
endforeach

conf.set_quoted('TELINIT', get_option('telinit-path'))

if run_command('ln', '--relative', '--help').returncode() != 0
        error('ln does not support --relative (added in coreutils 8.16)')
endif

############################################################

gperf = find_program('gperf')

gperf_test_format = '''
#include <string.h>
const char * in_word_set(const char *, @0@);
@1@
'''
gperf_snippet_format = 'echo foo,bar | @0@ -L ANSI-C'
gperf_snippet = run_command('sh', '-c', gperf_snippet_format.format(gperf.path()))
gperf_test = gperf_test_format.format('size_t', gperf_snippet.stdout())
if cc.compiles(gperf_test)
        gperf_len_type = 'size_t'
else
        gperf_test = gperf_test_format.format('unsigned', gperf_snippet.stdout())
        if cc.compiles(gperf_test)
                gperf_len_type = 'unsigned'
        else
                error('unable to determine gperf len type')
        endif
endif
message('gperf len type is @0@'.format(gperf_len_type))
conf.set('GPERF_LEN_TYPE', gperf_len_type,
         description : 'The type of gperf "len" parameter')

############################################################

if not cc.has_header('sys/capability.h')
        error('POSIX caps headers not found')
endif
foreach header : ['crypt.h',
                  'linux/memfd.h',
                  'linux/vm_sockets.h',
                  'sys/auxv.h',
                  'valgrind/memcheck.h',
                  'valgrind/valgrind.h',
                 ]

        conf.set10('HAVE_' + header.underscorify().to_upper(),
                   cc.has_header(header))
endforeach

############################################################

conf.set_quoted('FALLBACK_HOSTNAME', get_option('fallback-hostname'))
conf.set10('ENABLE_COMPAT_GATEWAY_HOSTNAME', get_option('compat-gateway-hostname'))
gateway_hostnames = ['_gateway'] + (conf.get('ENABLE_COMPAT_GATEWAY_HOSTNAME') == 1 ? ['gateway'] : [])

default_hierarchy = get_option('default-hierarchy')
conf.set_quoted('DEFAULT_HIERARCHY_NAME', default_hierarchy,
                description : 'default cgroup hierarchy as string')
if default_hierarchy == 'legacy'
        conf.set('DEFAULT_HIERARCHY', 'CGROUP_UNIFIED_NONE')
elif default_hierarchy == 'hybrid'
        conf.set('DEFAULT_HIERARCHY', 'CGROUP_UNIFIED_SYSTEMD')
else
        conf.set('DEFAULT_HIERARCHY', 'CGROUP_UNIFIED_ALL')
endif

default_net_naming_scheme = get_option('default-net-naming-scheme')
conf.set_quoted('DEFAULT_NET_NAMING_SCHEME', default_net_naming_scheme)

time_epoch = get_option('time-epoch')
if time_epoch == -1
        NEWS = files('NEWS')
        time_epoch = run_command(stat, '-c', '%Y', NEWS).stdout().to_int()
endif
conf.set('TIME_EPOCH', time_epoch)

system_uid_max = get_option('system-uid-max')
if system_uid_max == -1
        system_uid_max = run_command(
                awk,
                '/^\s*SYS_UID_MAX\s+/ { uid=$2 } END { print uid }',
                '/etc/login.defs').stdout().strip()
        if system_uid_max == ''
                system_uid_max = 999
        else
                system_uid_max = system_uid_max.to_int()
        endif
endif
conf.set('SYSTEM_UID_MAX', system_uid_max)
substs.set('systemuidmax', system_uid_max)

system_gid_max = get_option('system-gid-max')
if system_gid_max == -1
        system_gid_max = run_command(
                awk,
                '/^\s*SYS_GID_MAX\s+/ { gid=$2 } END { print gid }',
                '/etc/login.defs').stdout().strip()
        if system_gid_max == ''
                system_gid_max = 999
        else
                system_gid_max = system_gid_max.to_int()
        endif
endif
conf.set('SYSTEM_GID_MAX', system_gid_max)
substs.set('systemgidmax', system_gid_max)

dynamic_uid_min = get_option('dynamic-uid-min')
dynamic_uid_max = get_option('dynamic-uid-max')
conf.set('DYNAMIC_UID_MIN', dynamic_uid_min)
conf.set('DYNAMIC_UID_MAX', dynamic_uid_max)
substs.set('dynamicuidmin', dynamic_uid_min)
substs.set('dynamicuidmax', dynamic_uid_max)

container_uid_base_min = get_option('container-uid-base-min')
container_uid_base_max = get_option('container-uid-base-max')
conf.set('CONTAINER_UID_BASE_MIN', container_uid_base_min)
conf.set('CONTAINER_UID_BASE_MAX', container_uid_base_max)
substs.set('containeruidbasemin', container_uid_base_min)
substs.set('containeruidbasemax', container_uid_base_max)

nobody_user = get_option('nobody-user')
nobody_group = get_option('nobody-group')

if not meson.is_cross_build()
        getent_result = run_command('getent', 'passwd', '65534')
        if getent_result.returncode() == 0
                name = getent_result.stdout().split(':')[0]
                if name != nobody_user
                        warning('\n' +
                                'The local user with the UID 65534 does not match the configured user name "@0@" of the nobody user (its name is @1@).\n'.format(nobody_user, name) +
                                'Your build will result in an user table setup that is incompatible with the local system.')
                endif
        endif
        id_result = run_command('id', '-u', nobody_user)
        if id_result.returncode() == 0
                id = id_result.stdout().to_int()
                if id != 65534
                        warning('\n' +
                                'The local user with the configured user name "@0@" of the nobody user does not have UID 65534 (it has @1@).\n'.format(nobody_user, id) +
                                'Your build will result in an user table setup that is incompatible with the local system.')
                endif
        endif

        getent_result = run_command('getent', 'group', '65534')
        if getent_result.returncode() == 0
                name = getent_result.stdout().split(':')[0]
                if name != nobody_group
                        warning('\n' +
                                'The local group with the GID 65534 does not match the configured group name "@0@" of the nobody group (its name is @1@).\n'.format(nobody_group, name) +
                                'Your build will result in an group table setup that is incompatible with the local system.')
                endif
        endif
        id_result = run_command('id', '-g', nobody_group)
        if id_result.returncode() == 0
                id = id_result.stdout().to_int()
                if id != 65534
                        warning('\n' +
                                'The local group with the configured group name "@0@" of the nobody group does not have UID 65534 (it has @1@).\n'.format(nobody_group, id) +
                                'Your build will result in an group table setup that is incompatible with the local system.')
                endif
        endif
endif
if nobody_user != nobody_group and not (nobody_user == 'nobody' and nobody_group == 'nogroup')
        warning('\n' +
                'The configured user name "@0@" and group name "@0@" of the nobody user/group are not equivalent.\n'.format(nobody_user, nobody_group) +
                'Please re-check that both "nobody-user" and "nobody-group" options are correctly set.')
endif

conf.set_quoted('NOBODY_USER_NAME', nobody_user)
conf.set_quoted('NOBODY_GROUP_NAME', nobody_group)
substs.set('NOBODY_USER_NAME', nobody_user)
substs.set('NOBODY_GROUP_NAME', nobody_group)

tty_gid = get_option('tty-gid')
conf.set('TTY_GID', tty_gid)
substs.set('TTY_GID', tty_gid)

# Ensure provided GID argument is numeric, otherwise fallback to default assignment
users_gid = get_option('users-gid')
substs.set('USERS_GID', users_gid < 0 ? '-' : users_gid)

conf.set10('ENABLE_ADM_GROUP', get_option('adm-group'))
conf.set10('ENABLE_WHEEL_GROUP', get_option('wheel-group'))

dev_kvm_mode = get_option('dev-kvm-mode')
substs.set('DEV_KVM_MODE', dev_kvm_mode)
conf.set10('DEV_KVM_UACCESS', dev_kvm_mode != '0666')
group_render_mode = get_option('group-render-mode')
substs.set('GROUP_RENDER_MODE', group_render_mode)
conf.set10('GROUP_RENDER_UACCESS', group_render_mode != '0666')

kill_user_processes = get_option('default-kill-user-processes')
conf.set10('KILL_USER_PROCESSES', kill_user_processes)
conf.set_quoted('KILL_USER_PROCESSES_YES_NO', kill_user_processes ? 'yes' : 'no')
substs.set('KILL_USER_PROCESSES', kill_user_processes ? 'yes' : 'no')

dns_servers = get_option('dns-servers')
conf.set_quoted('DNS_SERVERS', dns_servers)
substs.set('DNS_SERVERS', dns_servers)

ntp_servers = get_option('ntp-servers')
conf.set_quoted('NTP_SERVERS', ntp_servers)
substs.set('NTP_SERVERS', ntp_servers)

default_locale = get_option('default-locale')
if default_locale == ''
        if not meson.is_cross_build()
                choose_default_locale_sh = find_program('tools/choose-default-locale.sh')
                default_locale = run_command(choose_default_locale_sh).stdout().strip()
        else
                default_locale = 'C.UTF-8'
        endif
endif
conf.set_quoted('SYSTEMD_DEFAULT_LOCALE', default_locale)

conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())

substs.set('SUSHELL', get_option('debug-shell'))
substs.set('DEBUGTTY', get_option('debug-tty'))
conf.set_quoted('DEBUGTTY', get_option('debug-tty'))

enable_debug_hashmap = false
enable_debug_mmap_cache = false
enable_debug_siphash = false
foreach name : get_option('debug-extra')
        if name == 'hashmap'
                enable_debug_hashmap = true
        elif name == 'mmap-cache'
                enable_debug_mmap_cache = true
        elif name == 'siphash'
                enable_debug_siphash = true
        else
                message('unknown debug option "@0@", ignoring'.format(name))
        endif
endforeach
conf.set10('ENABLE_DEBUG_HASHMAP', enable_debug_hashmap)
conf.set10('ENABLE_DEBUG_MMAP_CACHE', enable_debug_mmap_cache)
conf.set10('ENABLE_DEBUG_SIPHASH', enable_debug_siphash)

conf.set10('VALGRIND', get_option('valgrind'))
conf.set10('LOG_TRACE', get_option('log-trace'))

#####################################################################

threads = dependency('threads')
librt = cc.find_library('rt')
libm = cc.find_library('m')
libdl = cc.find_library('dl')
libcrypt = cc.find_library('crypt')

libcap = dependency('libcap', required : false)
if not libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap = cc.find_library('cap')
endif

libmount = dependency('mount',
                      version : fuzzer_build ? '>= 0' : '>= 2.30')

want_seccomp = get_option('seccomp')
if want_seccomp != 'false' and not skip_deps
        libseccomp = dependency('libseccomp',
                                version : '>= 2.3.1',
                                required : want_seccomp == 'true')
        have = libseccomp.found()
else
        have = false
        libseccomp = []
endif
conf.set10('HAVE_SECCOMP', have)

want_selinux = get_option('selinux')
if want_selinux != 'false' and not skip_deps
        libselinux = dependency('libselinux',
                                version : '>= 2.1.9',
                                required : want_selinux == 'true')
        have = libselinux.found()
else
        have = false
        libselinux = []
endif
conf.set10('HAVE_SELINUX', have)

want_apparmor = get_option('apparmor')
if want_apparmor != 'false' and not skip_deps
        libapparmor = dependency('libapparmor',
                                 required : want_apparmor == 'true')
        have = libapparmor.found()
else
        have = false
        libapparmor = []
endif
conf.set10('HAVE_APPARMOR', have)

smack_run_label = get_option('smack-run-label')
if smack_run_label != ''
        conf.set_quoted('SMACK_RUN_LABEL', smack_run_label)
endif

want_polkit = get_option('polkit')
install_polkit = false
install_polkit_pkla = false
if want_polkit != 'false' and not skip_deps
        install_polkit = true

        libpolkit = dependency('polkit-gobject-1',
                               required : false)
        if libpolkit.found() and libpolkit.version().version_compare('< 0.106')
                message('Old polkit detected, will install pkla files')
                install_polkit_pkla = true
        endif
endif
conf.set10('ENABLE_POLKIT', install_polkit)

want_acl = get_option('acl')
if want_acl != 'false' and not skip_deps
        libacl = cc.find_library('acl', required : want_acl == 'true')
        have = libacl.found()
else
        have = false
        libacl = []
endif
conf.set10('HAVE_ACL', have)

want_audit = get_option('audit')
if want_audit != 'false' and not skip_deps
        libaudit = dependency('audit', required : want_audit == 'true')
        have = libaudit.found()
else
        have = false
        libaudit = []
endif
conf.set10('HAVE_AUDIT', have)

want_blkid = get_option('blkid')
if want_blkid != 'false' and not skip_deps
        libblkid = dependency('blkid', required : want_blkid == 'true')
        have = libblkid.found()
else
        have = false
        libblkid = []
endif
conf.set10('HAVE_BLKID', have)

want_kmod = get_option('kmod')
if want_kmod != 'false' and not skip_deps
        libkmod = dependency('libkmod',
                             version : '>= 15',
                             required : want_kmod == 'true')
        have = libkmod.found()
else
        have = false
        libkmod = []
endif
conf.set10('HAVE_KMOD', have)

want_pam = get_option('pam')
if want_pam != 'false' and not skip_deps
        libpam = cc.find_library('pam', required : want_pam == 'true')
        libpam_misc = cc.find_library('pam_misc', required : want_pam == 'true')
        have = libpam.found() and libpam_misc.found()
else
        have = false
        libpam = []
        libpam_misc = []
endif
conf.set10('HAVE_PAM', have)

want_microhttpd = get_option('microhttpd')
if want_microhttpd != 'false' and not skip_deps
        libmicrohttpd = dependency('libmicrohttpd',
                                   version : '>= 0.9.33',
                                   required : want_microhttpd == 'true')
        have = libmicrohttpd.found()
else
        have = false
        libmicrohttpd = []
endif
conf.set10('HAVE_MICROHTTPD', have)

want_libcryptsetup = get_option('libcryptsetup')
if want_libcryptsetup != 'false' and not skip_deps
        libcryptsetup = dependency('libcryptsetup',
                                   version : '>= 1.6.0',
                                   required : want_libcryptsetup == 'true')
        have = libcryptsetup.found()
        have_sector = cc.has_member(
                    'struct crypt_params_plain',
                    'sector_size',
                    prefix : '#include <libcryptsetup.h>')
else
        have = false
        have_sector = false
        libcryptsetup = []
endif
conf.set10('HAVE_LIBCRYPTSETUP', have)
conf.set10('HAVE_LIBCRYPTSETUP_SECTOR_SIZE', have_sector)

want_libcurl = get_option('libcurl')
if want_libcurl != 'false' and not skip_deps
        libcurl = dependency('libcurl',
                             version : '>= 7.32.0',
                             required : want_libcurl == 'true')
        have = libcurl.found()
else
        have = false
        libcurl = []
endif
conf.set10('HAVE_LIBCURL', have)

want_libidn = get_option('libidn')
want_libidn2 = get_option('libidn2')
if want_libidn == 'true' and want_libidn2 == 'true'
        error('libidn and libidn2 cannot be requested simultaneously')
endif

if want_libidn2 != 'false' and want_libidn != 'true' and not skip_deps
        libidn = dependency('libidn2',
                            required : want_libidn2 == 'true')
        have = libidn.found()
else
        have = false
        libidn = []
endif
conf.set10('HAVE_LIBIDN2', have)
if not have and want_libidn != 'false' and not skip_deps
        # libidn is used for both libidn and libidn2 objects
        libidn = dependency('libidn',
                            required : want_libidn == 'true')
        have = libidn.found()
else
        have = false
endif
conf.set10('HAVE_LIBIDN', have)

want_libiptc = get_option('libiptc')
if want_libiptc != 'false' and not skip_deps
        libiptc = dependency('libiptc',
                             required : want_libiptc == 'true')
        have = libiptc.found()
else
        have = false
        libiptc = []
endif
conf.set10('HAVE_LIBIPTC', have)

want_qrencode = get_option('qrencode')
if want_qrencode != 'false' and not skip_deps
        libqrencode = dependency('libqrencode',
                                 required : want_qrencode == 'true')
        have = libqrencode.found()
else
        have = false
        libqrencode = []
endif
conf.set10('HAVE_QRENCODE', have)

want_gcrypt = get_option('gcrypt')
if want_gcrypt != 'false' and not skip_deps
        libgcrypt = cc.find_library('gcrypt', required : want_gcrypt == 'true')
        libgpg_error = cc.find_library('gpg-error', required : want_gcrypt == 'true')
        have = libgcrypt.found() and libgpg_error.found()
else
        have = false
endif
if not have
        # link to neither of the libs if one is not found
        libgcrypt = []
        libgpg_error = []
endif
conf.set10('HAVE_GCRYPT', have)

want_gnutls = get_option('gnutls')
if want_gnutls != 'false' and not skip_deps
        libgnutls = dependency('gnutls',
                               version : '>= 3.1.4',
                               required : want_gnutls == 'true')
        have = libgnutls.found()
else
        have = false
        libgnutls = []
endif
conf.set10('HAVE_GNUTLS', have)

want_openssl = get_option('openssl')
if want_openssl != 'false' and not skip_deps
        libopenssl = dependency('openssl',
                                version : '>= 1.1.0',
                                required : want_openssl == 'true')
        have = libopenssl.found()
else
        have = false
        libopenssl = []
endif
conf.set10('HAVE_OPENSSL', have)

want_elfutils = get_option('elfutils')
if want_elfutils != 'false' and not skip_deps
        libdw = dependency('libdw',
                           required : want_elfutils == 'true')
        have = libdw.found()
else
        have = false
        libdw = []
endif
conf.set10('HAVE_ELFUTILS', have)

want_zlib = get_option('zlib')
if want_zlib != 'false' and not skip_deps
        libz = dependency('zlib',
                          required : want_zlib == 'true')
        have = libz.found()
else
        have = false
        libz = []
endif
conf.set10('HAVE_ZLIB', have)

want_bzip2 = get_option('bzip2')
if want_bzip2 != 'false' and not skip_deps
        libbzip2 = cc.find_library('bz2',
                                   required : want_bzip2 == 'true')
        have = libbzip2.found()
else
        have = false
        libbzip2 = []
endif
conf.set10('HAVE_BZIP2', have)

want_xz = get_option('xz')
if want_xz != 'false' and not skip_deps
        libxz = dependency('liblzma',
                           required : want_xz == 'true')
        have = libxz.found()
else
        have = false
        libxz = []
endif
conf.set10('HAVE_XZ', have)

want_lz4 = get_option('lz4')
if want_lz4 != 'false' and not skip_deps
        liblz4 = dependency('liblz4',
                            version : '>= 1.3.0',
                            required : want_lz4 == 'true')
        have = liblz4.found()
else
        have = false
        liblz4 = []
endif
conf.set10('HAVE_LZ4', have)

want_xkbcommon = get_option('xkbcommon')
if want_xkbcommon != 'false' and not skip_deps
        libxkbcommon = dependency('xkbcommon',
                                  version : '>= 0.3.0',
                                  required : want_xkbcommon == 'true')
        have = libxkbcommon.found()
else
        have = false
        libxkbcommon = []
endif
conf.set10('HAVE_XKBCOMMON', have)

want_pcre2 = get_option('pcre2')
if want_pcre2 != 'false'
        libpcre2 = dependency('libpcre2-8',
                              required : want_pcre2 == 'true')
        have = libpcre2.found()
else
        have = false
        libpcre2 = []
endif
conf.set10('HAVE_PCRE2', have)

want_glib = get_option('glib')
if want_glib != 'false' and not skip_deps
        libglib =    dependency('glib-2.0',
                                version : '>= 2.22.0',
                                required : want_glib == 'true')
        libgobject = dependency('gobject-2.0',
                                version : '>= 2.22.0',
                                required : want_glib == 'true')
        libgio =     dependency('gio-2.0',
                                required : want_glib == 'true')
        have = libglib.found() and libgobject.found() and libgio.found()
else
        have = false
        libglib = []
        libgobject = []
        libgio = []
endif
conf.set10('HAVE_GLIB', have)

want_dbus = get_option('dbus')
if want_dbus != 'false' and not skip_deps
        libdbus = dependency('dbus-1',
                             version : '>= 1.3.2',
                             required : want_dbus == 'true')
        have = libdbus.found()
else
        have = false
        libdbus = []
endif
conf.set10('HAVE_DBUS', have)

default_dnssec = get_option('default-dnssec')
if skip_deps
        default_dnssec = 'no'
endif
if default_dnssec != 'no' and conf.get('HAVE_GCRYPT') == 0
        message('default-dnssec cannot be set to yes or allow-downgrade when gcrypt is disabled. Setting default-dnssec to no.')
        default_dnssec = 'no'
endif
conf.set('DEFAULT_DNSSEC_MODE',
         'DNSSEC_' + default_dnssec.underscorify().to_upper())
substs.set('DEFAULT_DNSSEC_MODE', default_dnssec)

dns_over_tls = get_option('dns-over-tls')
if dns_over_tls != 'false'
        if dns_over_tls == 'openssl'
                have_gnutls = false
        else
                have_gnutls = (conf.get('HAVE_GNUTLS') == 1 and libgnutls.version().version_compare('>= 3.5.3'))
                if dns_over_tls == 'gnutls' and not have_gnutls
                        error('DNS-over-TLS support was requested with gnutls, but dependencies are not available')
                endif
        endif
        if dns_over_tls == 'gnutls' or have_gnutls
                have_openssl = false
        else
                have_openssl = conf.get('HAVE_OPENSSL') == 1
                if dns_over_tls != 'auto' and not have_openssl
                        str = dns_over_tls == 'openssl' ? ' with openssl' : ''
                        error('DNS-over-TLS support was requested@0@, but dependencies are not available'.format(str))
                endif
        endif
        have = have_gnutls or have_openssl
else
        have = false
        have_gnutls = false
        have_openssl = false
endif
conf.set10('ENABLE_DNS_OVER_TLS', have)
conf.set10('DNS_OVER_TLS_USE_GNUTLS', have_gnutls)
conf.set10('DNS_OVER_TLS_USE_OPENSSL', have_openssl)

default_dns_over_tls = get_option('default-dns-over-tls')
if skip_deps
        default_dns_over_tls = 'no'
endif
if default_dns_over_tls != 'no' and conf.get('ENABLE_DNS_OVER_TLS') == 0
        message('default-dns-over-tls cannot be enabled or set to opportunistic when DNS-over-TLS support is disabled. Setting default-dns-over-tls to no.')
        default_dns_over_tls = 'no'
endif
conf.set('DEFAULT_DNS_OVER_TLS_MODE',
         'DNS_OVER_TLS_' + default_dns_over_tls.underscorify().to_upper())
substs.set('DEFAULT_DNS_OVER_TLS_MODE', default_dns_over_tls)

want_importd = get_option('importd')
if want_importd != 'false'
        have = (conf.get('HAVE_LIBCURL') == 1 and
                conf.get('HAVE_ZLIB') == 1 and
                conf.get('HAVE_XZ') == 1 and
                conf.get('HAVE_GCRYPT') == 1)
        if want_importd == 'true' and not have
                error('importd support was requested, but dependencies are not available')
        endif
else
        have = false
endif
conf.set10('ENABLE_IMPORTD', have)

want_remote = get_option('remote')
if want_remote != 'false'
        have_deps = [conf.get('HAVE_MICROHTTPD') == 1,
                     conf.get('HAVE_LIBCURL') == 1]
        # sd-j-remote requires µhttpd, and sd-j-upload requires libcurl, so
        # it's possible to build one without the other. Complain only if
        # support was explicitly requested. The auxiliary files like sysusers
        # config should be installed when any of the programs are built.
        if want_remote == 'true' and not (have_deps[0] and have_deps[1])
                error('remote support was requested, but dependencies are not available')
        endif
        have = have_deps[0] or have_deps[1]
else
        have = false
endif
conf.set10('ENABLE_REMOTE', have)

foreach term : ['utmp',
                'hibernate',
                'environment-d',
                'binfmt',
                'coredump',
                'pstore',
                'resolve',
                'logind',
                'hostnamed',
                'localed',
                'machined',
                'portabled',
                'networkd',
                'timedated',
                'timesyncd',
                'firstboot',
                'randomseed',
                'backlight',
                'vconsole',
                'quotacheck',
                'sysusers',
                'tmpfiles',
                'hwdb',
                'rfkill',
                'ldconfig',
                'efi',
                'tpm',
                'ima',
                'smack',
                'gshadow',
                'idn',
                'nss-myhostname',
                'nss-systemd']
        have = get_option(term)
        name = 'ENABLE_' + term.underscorify().to_upper()
        conf.set10(name, have)
endforeach

foreach tuple : [['nss-mymachines', 'machined'],
                 ['nss-resolve',    'resolve']]
        want = get_option(tuple[0])
        if want != 'false'
                have = get_option(tuple[1])
                if want == 'true' and not have
                        error('@0@ is requested but @1@ is disabled'.format(tuple[0], tuple[1]))
                endif
        else
                have = false
        endif
        name = 'ENABLE_' + tuple[0].underscorify().to_upper()
        conf.set10(name, have)
endforeach

enable_nss = false
foreach term : ['ENABLE_NSS_MYHOSTNAME',
                'ENABLE_NSS_MYMACHINES',
                'ENABLE_NSS_RESOLVE',
                'ENABLE_NSS_SYSTEMD']
        if conf.get(term) == 1
                enable_nss = true
        endif
endforeach
conf.set10('ENABLE_NSS', enable_nss)

conf.set10('ENABLE_TIMEDATECTL', get_option('timedated') or get_option('timesyncd'))

tests = []
fuzzers = []

conf.set10('SYSTEMD_SLOW_TESTS_DEFAULT', slow_tests)

#####################################################################

if get_option('efi')
        efi_arch = host_machine.cpu_family()

        if efi_arch == 'x86'
                EFI_MACHINE_TYPE_NAME = 'ia32'
                gnu_efi_arch = 'ia32'
        elif efi_arch == 'x86_64'
                EFI_MACHINE_TYPE_NAME = 'x64'
                gnu_efi_arch = 'x86_64'
        elif efi_arch == 'arm'
                EFI_MACHINE_TYPE_NAME = 'arm'
                gnu_efi_arch = 'arm'
        elif efi_arch == 'aarch64'
                EFI_MACHINE_TYPE_NAME = 'aa64'
                gnu_efi_arch = 'aarch64'
        else
                EFI_MACHINE_TYPE_NAME = ''
                gnu_efi_arch = ''
        endif

        have = true
        conf.set_quoted('EFI_MACHINE_TYPE_NAME', EFI_MACHINE_TYPE_NAME)

        conf.set('SD_TPM_PCR', get_option('tpm-pcrindex'))
else
        have = false
endif
conf.set10('ENABLE_EFI', have)

#####################################################################

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

meson_apply_m4 = find_program('tools/meson-apply-m4.sh')

includes = include_directories('src/basic',
                               'src/boot',
                               'src/shared',
                               'src/systemd',
                               'src/journal',
                               'src/journal-remote',
                               'src/nspawn',
                               'src/resolve',
                               'src/timesync',
                               'src/time-wait-sync',
                               'src/login',
                               'src/udev',
                               'src/libudev',
                               'src/core',
                               'src/shutdown',
                               'src/libsystemd/sd-bus',
                               'src/libsystemd/sd-device',
                               'src/libsystemd/sd-event',
                               'src/libsystemd/sd-hwdb',
                               'src/libsystemd/sd-id128',
                               'src/libsystemd/sd-netlink',
                               'src/libsystemd/sd-network',
                               'src/libsystemd/sd-resolve',
                               'src/libsystemd-network',
                               '.')

add_project_arguments('-include', 'config.h', language : 'c')

generate_gperfs = find_program('tools/generate-gperfs.py')

subdir('po')
subdir('catalog')
subdir('src/systemd')
subdir('src/basic')
subdir('src/libsystemd')
subdir('src/libsystemd-network')
subdir('src/journal')
subdir('src/login')

libjournal_core = static_library(
        'journal-core',
        libjournal_core_sources,
        journald_gperf_c,
        include_directories : includes,
        install : false)

libsystemd_sym_path = '@0@/@1@'.format(project_source_root, libsystemd_sym)
libsystemd = shared_library(
        'systemd',
        disable_mempool_c,
        version : libsystemd_version,
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libsystemd_sym_path],
        link_with : [libbasic,
                     libbasic_gcrypt],
        link_whole : [libsystemd_static,
                      libjournal_client],
        dependencies : [threads,
                        librt,
                        libxz,
                        liblz4],
        link_depends : libsystemd_sym,
        install : true,
        install_dir : rootlibdir)

static_libsystemd = get_option('static-libsystemd')
static_libsystemd_pic = static_libsystemd == 'true' or static_libsystemd == 'pic'

install_libsystemd_static = static_library(
        'systemd',
        libsystemd_sources,
        journal_client_sources,
        basic_sources,
        basic_gcrypt_sources,
        disable_mempool_c,
        include_directories : includes,
        build_by_default : static_libsystemd != 'false',
        install : static_libsystemd != 'false',
        install_dir : rootlibdir,
        pic : static_libsystemd == 'true' or static_libsystemd == 'pic',
        dependencies : [threads,
                        librt,
                        libxz,
                        liblz4,
                        libcap,
                        libblkid,
                        libmount,
                        libselinux,
                        libgcrypt],
        c_args : libsystemd_c_args + (static_libsystemd_pic ? [] : ['-fno-PIC']))

############################################################

# binaries that have --help and are intended for use by humans,
# usually, but not always, installed in /bin.
public_programs = []

subdir('src/libudev')
subdir('src/shared')
subdir('src/core')
subdir('src/shutdown')
subdir('src/udev')
subdir('src/network')

subdir('src/analyze')
subdir('src/journal-remote')
subdir('src/coredump')
subdir('src/pstore')
subdir('src/hostname')
subdir('src/import')
subdir('src/kernel-install')
subdir('src/locale')
subdir('src/machine')
subdir('src/portable')
subdir('src/nspawn')
subdir('src/resolve')
subdir('src/timedate')
subdir('src/timesync')
subdir('src/vconsole')
subdir('src/boot/efi')

subdir('src/test')
subdir('src/fuzz')
subdir('rules')
subdir('test')

############################################################

# only static linking apart from libdl, to make sure that the
# module is linked to all libraries that it uses.
test_dlopen = executable(
        'test-dlopen',
        test_dlopen_c,
        disable_mempool_c,
        include_directories : includes,
        link_with : [libbasic],
        dependencies : [libdl],
        build_by_default : want_tests != 'false')

foreach tuple : [['myhostname', 'ENABLE_NSS_MYHOSTNAME'],
                 ['systemd',    'ENABLE_NSS_SYSTEMD'],
                 ['mymachines', 'ENABLE_NSS_MYMACHINES'],
                 ['resolve',    'ENABLE_NSS_RESOLVE']]

        condition = tuple[1] == '' or conf.get(tuple[1]) == 1
        if condition
                module = tuple[0]

                sym = 'src/nss-@0@/nss-@0@.sym'.format(module)
                version_script_arg = join_paths(project_source_root, sym)

                nss = shared_library(
                        'nss_' + module,
                        'src/nss-@0@/nss-@0@.c'.format(module),
                        disable_mempool_c,
                        version : '2',
                        include_directories : includes,
                        # Note that we link NSS modules with '-z nodelete' so that mempools never get orphaned
                        link_args : ['-Wl,-z,nodelete',
                                     '-shared',
                                     '-Wl,--version-script=' + version_script_arg],
                        link_with : [libsystemd_static,
                                     libshared_static,
                                     libbasic],
                        dependencies : [threads,
                                        librt],
                        link_depends : sym,
                        install : true,
                        install_dir : rootlibdir)

                # We cannot use shared_module because it does not support version suffix.
                # Unfortunately shared_library insists on creating the symlink…
                meson.add_install_script('sh', '-c',
                                         'rm $DESTDIR@0@/libnss_@1@.so'
                                         .format(rootlibdir, module))

                if want_tests != 'false'
                        test('dlopen-nss_' + module,
                             test_dlopen,
                             # path to dlopen must include a slash
                             args : nss.full_path())
                endif
        endif
endforeach

############################################################

executable('systemd',
           systemd_sources,
           include_directories : includes,
           link_with : [libcore,
                        libshared],
           dependencies : [versiondep,
                           threads,
                           librt,
                           libseccomp,
                           libselinux,
                           libmount,
                           libblkid],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

meson.add_install_script(meson_make_symlink,
                         join_paths(rootlibexecdir, 'systemd'),
                         join_paths(rootsbindir, 'init'))

exe = executable('systemd-analyze',
                 systemd_analyze_sources,
                 include_directories : includes,
                 link_with : [libcore,
                              libshared],
                 dependencies : [versiondep,
                                 threads,
                                 librt,
                                 libseccomp,
                                 libselinux,
                                 libmount,
                                 libblkid],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

executable('systemd-journald',
           systemd_journald_sources,
           include_directories : includes,
           link_with : [libjournal_core,
                        libshared],
           dependencies : [threads,
                           libxz,
                           liblz4,
                           libselinux],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-cat',
                 systemd_cat_sources,
                 include_directories : includes,
                 link_with : [libjournal_core,
                              libshared],
                 dependencies : [threads],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('journalctl',
                 journalctl_sources,
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads,
                                 libqrencode,
                                 libxz,
                                 liblz4,
                                 libpcre2],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

executable('systemd-getty-generator',
           'src/getty-generator/getty-generator.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

executable('systemd-debug-generator',
           'src/debug-generator/debug-generator.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

executable('systemd-run-generator',
           'src/run-generator/run-generator.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

executable('systemd-fstab-generator',
           'src/fstab-generator/fstab-generator.c',
           include_directories : includes,
           link_with : [libcore_shared,
                        libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

if conf.get('ENABLE_ENVIRONMENT_D') == 1
        executable('30-systemd-environment-d-generator',
                   'src/environment-d-generator/environment-d-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : userenvgeneratordir)

        meson.add_install_script(meson_make_symlink,
                                 join_paths(sysconfdir, 'environment'),
                                 join_paths(environmentdir, '99-environment.conf'))
endif

if conf.get('ENABLE_HIBERNATE') == 1
        executable('systemd-hibernate-resume-generator',
                   'src/hibernate-resume/hibernate-resume-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)

        executable('systemd-hibernate-resume',
                   'src/hibernate-resume/hibernate-resume.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('HAVE_BLKID') == 1
        executable('systemd-gpt-auto-generator',
                   'src/gpt-auto-generator/gpt-auto-generator.c',
                   'src/shared/blkid-util.h',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : libblkid,
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)

        exe = executable('systemd-dissect',
                         'src/dissect/dissect.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootlibexecdir)
        public_programs += exe
endif

if conf.get('ENABLE_RESOLVE') == 1
        executable('systemd-resolved',
                   systemd_resolved_sources,
                   include_directories : includes,
                   link_with : [libshared,
                                libbasic_gcrypt,
                                libsystemd_resolve_core],
                   dependencies : systemd_resolved_dependencies,
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('resolvectl',
                         resolvectl_sources,
                         include_directories : includes,
                         link_with : [libshared,
                                      libbasic_gcrypt,
                                      libsystemd_resolve_core],
                         dependencies : [threads,
                                         libgpg_error,
                                         libm,
                                         libidn],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += exe

        meson.add_install_script(meson_make_symlink,
                         join_paths(bindir, 'resolvectl'),
                         join_paths(rootsbindir, 'resolvconf'))

        meson.add_install_script(meson_make_symlink,
                         join_paths(bindir, 'resolvectl'),
                         join_paths(bindir, 'systemd-resolve'))
endif

if conf.get('ENABLE_LOGIND') == 1
        executable('systemd-logind',
                   systemd_logind_sources,
                   include_directories : includes,
                   link_with : [liblogind_core,
                                libshared],
                   dependencies : [threads,
                                   libacl],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('loginctl',
                         loginctl_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads,
                                         liblz4,
                                         libxz],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe

        exe = executable('systemd-inhibit',
                         'src/login/inhibit.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe

        if conf.get('HAVE_PAM') == 1
                version_script_arg = join_paths(project_source_root, pam_systemd_sym)
                pam_systemd = shared_library(
                        'pam_systemd',
                        pam_systemd_c,
                        name_prefix : '',
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + version_script_arg],
                        link_with : [libsystemd_static,
                                     libshared_static],
                        dependencies : [threads,
                                        libpam,
                                        libpam_misc],
                        link_depends : pam_systemd_sym,
                        install : true,
                        install_dir : pamlibdir)

                if want_tests != 'false'
                        test('dlopen-pam_systemd',
                             test_dlopen,
                             # path to dlopen must include a slash
                             args : pam_systemd.full_path())
                endif
        endif

        executable('systemd-user-runtime-dir',
                   user_runtime_dir_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('HAVE_PAM') == 1
        executable('systemd-user-sessions',
                   'src/user-sessions/user-sessions.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_EFI') == 1 and conf.get('HAVE_BLKID') == 1
        exe = executable('bootctl',
                         'src/boot/bootctl.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [libblkid],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += exe

        executable('systemd-bless-boot',
                   'src/boot/bless-boot.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libblkid],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        executable('systemd-bless-boot-generator',
                   'src/boot/bless-boot-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)
endif

executable('systemd-boot-check-no-failures',
           'src/boot/boot-check-no-failures.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [libblkid],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-socket-activate', 'src/activate/activate.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe


if get_option('link-systemctl-shared')
        systemctl_link_with = [libshared]
else
        systemctl_link_with = [libsystemd_static,
                               libshared_static,
                               libjournal_client,
                               libbasic_gcrypt]
endif

exe = executable('systemctl',
                 'src/systemctl/systemctl.c',
                 'src/systemctl/sysv-compat.h',
                 'src/systemctl/sysv-compat.c',
                 include_directories : includes,
                 link_with : systemctl_link_with,
                 dependencies : [threads,
                                 libcap,
                                 libselinux,
                                 libxz,
                                 liblz4],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

if conf.get('ENABLE_PORTABLED') == 1
        executable('systemd-portabled',
                   systemd_portabled_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('portablectl', 'src/portable/portablectl.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe
endif

foreach alias : ['halt', 'poweroff', 'reboot', 'runlevel', 'shutdown', 'telinit']
        meson.add_install_script(meson_make_symlink,
                                 join_paths(rootbindir, 'systemctl'),
                                 join_paths(rootsbindir, alias))
endforeach

if conf.get('ENABLE_BACKLIGHT') == 1
        executable('systemd-backlight',
                   'src/backlight/backlight.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RFKILL') == 1
        executable('systemd-rfkill',
                   'src/rfkill/rfkill.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

executable('systemd-system-update-generator',
           'src/system-update-generator/system-update-generator.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

if conf.get('HAVE_LIBCRYPTSETUP') == 1
        executable('systemd-cryptsetup',
                   'src/cryptsetup/cryptsetup.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libcryptsetup],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        executable('systemd-cryptsetup-generator',
                   'src/cryptsetup/cryptsetup-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libcryptsetup],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)

        executable('systemd-veritysetup',
                   'src/veritysetup/veritysetup.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libcryptsetup],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        executable('systemd-veritysetup-generator',
                   'src/veritysetup/veritysetup-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libcryptsetup],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)
endif

if conf.get('HAVE_SYSV_COMPAT') == 1
        executable('systemd-sysv-generator',
                   'src/sysv-generator/sysv-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)

        executable('systemd-rc-local-generator',
                   'src/rc-local-generator/rc-local-generator.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : systemgeneratordir)
endif

if conf.get('ENABLE_HOSTNAMED') == 1
        executable('systemd-hostnamed',
                   'src/hostname/hostnamed.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('hostnamectl',
                         'src/hostname/hostnamectl.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += exe
endif

if conf.get('ENABLE_LOCALED') == 1
        if conf.get('HAVE_XKBCOMMON') == 1
                # logind will load libxkbcommon.so dynamically on its own
                deps = [libdl]
        else
                deps = []
        endif

        executable('systemd-localed',
                   systemd_localed_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : deps,
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('localectl',
                         localectl_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += exe
endif

if conf.get('ENABLE_TIMEDATED') == 1
        executable('systemd-timedated',
                   'src/timedate/timedated.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_TIMEDATECTL') == 1
        exe = executable('timedatectl',
                         'src/timedate/timedatectl.c',
                         include_directories : includes,
                         install_rpath : rootlibexecdir,
                         link_with : [libshared],
                         dependencies : [libm],
                         install : true)
        public_programs += exe
endif

if conf.get('ENABLE_TIMESYNCD') == 1
        executable('systemd-timesyncd',
                   systemd_timesyncd_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads,
                                   libm],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        executable('systemd-time-wait-sync',
                   'src/time-wait-sync/time-wait-sync.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_MACHINED') == 1
        executable('systemd-machined',
                   systemd_machined_sources,
                   include_directories : includes,
                   link_with : [libmachine_core,
                                libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('machinectl',
                         'src/machine/machinectl.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads,
                                         libxz,
                                         liblz4],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe
endif

if conf.get('ENABLE_IMPORTD') == 1
        executable('systemd-importd',
                   systemd_importd_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        systemd_pull = executable('systemd-pull',
                                  systemd_pull_sources,
                                  include_directories : includes,
                                  link_with : [libshared],
                                  dependencies : [versiondep,
                                                  libcurl,
                                                  libz,
                                                  libbzip2,
                                                  libxz,
                                                  libgcrypt],
                                  install_rpath : rootlibexecdir,
                                  install : true,
                                  install_dir : rootlibexecdir)

        systemd_import = executable('systemd-import',
                                    systemd_import_sources,
                                    include_directories : includes,
                                    link_with : [libshared],
                                    dependencies : [libcurl,
                                                    libz,
                                                    libbzip2,
                                                    libxz],
                                    install_rpath : rootlibexecdir,
                                    install : true,
                                    install_dir : rootlibexecdir)

        systemd_import_fs = executable('systemd-import-fs',
                                    systemd_import_fs_sources,
                                    include_directories : includes,
                                    link_with : [libshared],
                                    install_rpath : rootlibexecdir,
                                    install : true,
                                    install_dir : rootlibexecdir)

        systemd_export = executable('systemd-export',
                                    systemd_export_sources,
                                    include_directories : includes,
                                    link_with : [libshared],
                                    dependencies : [libcurl,
                                                    libz,
                                                    libbzip2,
                                                    libxz],
                                    install_rpath : rootlibexecdir,
                                    install : true,
                                    install_dir : rootlibexecdir)

        public_programs += [systemd_pull, systemd_import, systemd_import_fs, systemd_export]
endif

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_LIBCURL') == 1
        exe = executable('systemd-journal-upload',
                         systemd_journal_upload_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [versiondep,
                                         threads,
                                         libcurl,
                                         libgnutls,
                                         libxz,
                                         liblz4],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootlibexecdir)
        public_programs += exe
endif

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        s_j_remote = executable('systemd-journal-remote',
                                systemd_journal_remote_sources,
                                include_directories : includes,
                                link_with : [libshared,
                                             libsystemd_journal_remote],
                                dependencies : [threads,
                                                libmicrohttpd,
                                                libgnutls,
                                                libxz,
                                                liblz4],
                                install_rpath : rootlibexecdir,
                                install : true,
                                install_dir : rootlibexecdir)

        s_j_gatewayd = executable('systemd-journal-gatewayd',
                                  systemd_journal_gatewayd_sources,
                                  include_directories : includes,
                                  link_with : [libshared],
                                  dependencies : [threads,
                                                  libmicrohttpd,
                                                  libgnutls,
                                                  libxz,
                                                  liblz4],
                                  install_rpath : rootlibexecdir,
                                  install : true,
                                  install_dir : rootlibexecdir)
        public_programs += [s_j_remote, s_j_gatewayd]
endif

if conf.get('ENABLE_COREDUMP') == 1
        executable('systemd-coredump',
                   systemd_coredump_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads,
                                   libacl,
                                   libdw,
                                   libxz,
                                   liblz4],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('coredumpctl',
                         coredumpctl_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads,
                                         libxz,
                                         liblz4],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += exe
endif

if conf.get('ENABLE_PSTORE') == 1
        executable('systemd-pstore',
                   systemd_pstore_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads,
                                   libacl,
                                   libdw,
                                   libxz,
                                   liblz4],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_BINFMT') == 1
        exe = executable('systemd-binfmt',
                         'src/binfmt/binfmt.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootlibexecdir)
        public_programs += exe

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(binfmtdir))
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'binfmt.d')))
endif

if conf.get('ENABLE_VCONSOLE') == 1
        executable('systemd-vconsole-setup',
                   'src/vconsole/vconsole-setup.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RANDOMSEED') == 1
        executable('systemd-random-seed',
                   'src/random-seed/random-seed.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_FIRSTBOOT') == 1
        executable('systemd-firstboot',
                   'src/firstboot/firstboot.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libcrypt],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootbindir)
endif

executable('systemd-remount-fs',
           'src/remount-fs/remount-fs.c',
           include_directories : includes,
           link_with : [libcore_shared,
                        libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-machine-id-setup',
           'src/machine-id-setup/machine-id-setup-main.c',
           include_directories : includes,
           link_with : [libcore_shared,
                        libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootbindir)

executable('systemd-fsck',
           'src/fsck/fsck.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-growfs',
           'src/partition/growfs.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [libcryptsetup],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-makefs',
           'src/partition/makefs.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-sleep',
           'src/sleep/sleep.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

install_data('src/sleep/sleep.conf',
             install_dir : pkgsysconfdir)

exe = executable('systemd-sysctl',
                 'src/sysctl/sysctl.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootlibexecdir)
public_programs += exe

executable('systemd-ac-power',
           'src/ac-power/ac-power.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-detect-virt',
                 'src/detect-virt/detect-virt.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-delta',
                 'src/delta/delta.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-escape',
                 'src/escape/escape.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

exe = executable('systemd-notify',
                 'src/notify/notify.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

executable('systemd-volatile-root',
           'src/volatile-root/volatile-root.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-cgroups-agent',
           'src/cgroups-agent/cgroups-agent.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-id128',
                 'src/id128/id128.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-path',
                 'src/path/path.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-ask-password',
                 'src/ask-password/ask-password.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

executable('systemd-reply-password',
           'src/reply-password/reply-password.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-tty-ask-password-agent',
                 'src/tty-ask-password-agent/tty-ask-password-agent.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

exe = executable('systemd-cgls',
                 'src/cgls/cgls.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-cgtop',
                 'src/cgtop/cgtop.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

executable('systemd-initctl',
           'src/initctl/initctl.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-mount',
                 'src/mount/mount-tool.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies: [libmount],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

meson.add_install_script(meson_make_symlink,
                         'systemd-mount', join_paths(bindir, 'systemd-umount'))

exe = executable('systemd-run',
                 'src/run/run.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('systemd-stdio-bridge',
                 'src/stdio-bridge/stdio-bridge.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [versiondep],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

exe = executable('busctl',
                 'src/busctl/busctl.c',
                 'src/busctl/busctl-introspect.c',
                 'src/busctl/busctl-introspect.h',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

if conf.get('ENABLE_SYSUSERS') == 1
        exe = executable('systemd-sysusers',
                         'src/sysusers/sysusers.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe
endif

if conf.get('ENABLE_TMPFILES') == 1
        exe = executable('systemd-tmpfiles',
                         'src/tmpfiles/tmpfiles.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [libacl],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe

        if want_tests != 'false'
                test('test-systemd-tmpfiles',
                     test_systemd_tmpfiles_py,
                     # https://github.com/mesonbuild/meson/issues/2681
                     args : exe.full_path())
        endif
endif

if conf.get('ENABLE_HWDB') == 1
        exe = executable('systemd-hwdb',
                         'src/hwdb/hwdb.c',
                         'src/libsystemd/sd-hwdb/hwdb-internal.h',
                         include_directories : includes,
                         link_with : [libudev_static],
                         install_rpath : udev_rpath,
                         install : true,
                         install_dir : rootbindir)
        public_programs += exe
endif

if conf.get('ENABLE_QUOTACHECK') == 1
        executable('systemd-quotacheck',
                   'src/quotacheck/quotacheck.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

exe = executable('systemd-socket-proxyd',
                 'src/socket-proxy/socket-proxyd.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootlibexecdir)
public_programs += exe

exe = executable('systemd-udevd',
                 systemd_udevd_sources,
                 include_directories : includes,
                 c_args : '-DLOG_REALM=LOG_REALM_UDEV',
                 link_with : [libudev_core,
                              libsystemd_network,
                              libudev_static],
                 dependencies : [versiondep,
                                 threads,
                                 libkmod,
                                 libidn,
                                 libacl,
                                 libblkid],
                 install_rpath : udev_rpath,
                 install : true,
                 install_dir : rootlibexecdir)
public_programs += exe

exe = executable('udevadm',
                 udevadm_sources,
                 c_args : '-DLOG_REALM=LOG_REALM_UDEV',
                 include_directories : includes,
                 link_with : [libudev_core,
                              libsystemd_network,
                              libudev_static],
                 dependencies : [versiondep,
                                 threads,
                                 libkmod,
                                 libidn,
                                 libacl,
                                 libblkid],
                 install_rpath : udev_rpath,
                 install : true,
                 install_dir : rootbindir)
public_programs += exe

executable('systemd-shutdown',
           systemd_shutdown_sources,
           include_directories : includes,
           link_with : [libcore_shared,
                        libshared],
           dependencies : [libmount],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-update-done',
           'src/update-done/update-done.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-update-utmp',
           'src/update-utmp/update-utmp.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [libaudit],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

if conf.get('HAVE_KMOD') == 1
        executable('systemd-modules-load',
                   'src/modules-load/modules-load.c',
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libkmod],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(modulesloaddir))
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'modules-load.d')))
endif

exe = executable('systemd-nspawn',
                 systemd_nspawn_sources,
                 include_directories : includes,
                 link_with : [libcore_shared,
                              libnspawn_core,
                              libshared],
                 dependencies : [libblkid,
                                 libseccomp],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += exe

if conf.get('ENABLE_NETWORKD') == 1
        executable('systemd-networkd',
                   systemd_networkd_sources,
                   include_directories : includes,
                   link_with : [libnetworkd_core,
                                libsystemd_network,
                                libudev_static,
                                libshared],
                   dependencies : [threads],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        executable('systemd-networkd-wait-online',
                   systemd_networkd_wait_online_sources,
                   include_directories : includes,
                   link_with : [libnetworkd_core,
                                libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('networkctl',
                   networkctl_sources,
                   include_directories : includes,
                   link_with : [libsystemd_network,
                              libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootbindir)
        public_programs += exe

        executable('systemd-network-generator',
                   network_generator_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

executable('systemd-sulogin-shell',
           ['src/sulogin-shell/sulogin-shell.c'],
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

############################################################

custom_target(
        'systemd-runtest.env',
        output : 'systemd-runtest.env',
        command : ['sh', '-c', '{ ' +
                   'echo SYSTEMD_TEST_DATA=@0@; '.format(join_paths(project_source_root, 'test')) +
                   'echo SYSTEMD_CATALOG_DIR=@0@; '.format(join_paths(meson.current_build_dir(), 'catalog')) +
                   '} >@OUTPUT@'],
        build_by_default : true)

foreach tuple : tests
        sources = tuple[0]
        link_with = tuple[1].length() > 0 ? tuple[1] : [libshared]
        dependencies = tuple[2]
        condition = tuple.length() >= 4 ? tuple[3] : ''
        type = tuple.length() >= 5 ? tuple[4] : ''
        defs = tuple.length() >= 6 ? tuple[5] : []
        incs = tuple.length() >= 7 ? tuple[6] : includes
        timeout = 30

        name = sources[0].split('/')[-1].split('.')[0]
        if type.startswith('timeout=')
                timeout = type.split('=')[1].to_int()
                type = ''
        endif

        if condition == '' or conf.get(condition) == 1
                exe = executable(
                        name,
                        sources,
                        include_directories : incs,
                        link_with : link_with,
                        dependencies : [versiondep,
                                        dependencies],
                        c_args : defs,
                        build_by_default : want_tests != 'false',
                        install_rpath : rootlibexecdir,
                        install : install_tests,
                        install_dir : join_paths(testsdir, type))

                if type == 'manual'
                        message('@0@ is a manual test'.format(name))
                elif type == 'unsafe' and want_tests != 'unsafe'
                        message('@0@ is an unsafe test'.format(name))
                elif want_tests != 'false'
                        test(name, exe,
                             env : test_env,
                             timeout : timeout)
                endif
        else
                message('Not compiling @0@ because @1@ is not true'.format(name, condition))
        endif
endforeach

exe = executable(
        'test-libsystemd-sym',
        test_libsystemd_sym_c,
        include_directories : includes,
        link_with : [libsystemd],
        build_by_default : want_tests != 'false',
        install : install_tests,
        install_dir : testsdir)
if want_tests != 'false'
        test('test-libsystemd-sym', exe)
endif

exe = executable(
        'test-libsystemd-static-sym',
        test_libsystemd_sym_c,
        include_directories : includes,
        link_with : [install_libsystemd_static],
        dependencies : [threads], # threads is already included in dependencies on the library,
                                  # but does not seem to get propagated. Add here as a work-around.
        build_by_default : want_tests != 'false' and static_libsystemd_pic,
        install : install_tests and static_libsystemd_pic,
        install_dir : testsdir)
if want_tests != 'false' and static_libsystemd_pic
        test('test-libsystemd-static-sym', exe)
endif

exe = executable(
        'test-libudev-sym',
        test_libudev_sym_c,
        include_directories : includes,
        c_args : '-Wno-deprecated-declarations',
        link_with : [libudev],
        build_by_default : want_tests != 'false',
        install : install_tests,
        install_dir : testsdir)
if want_tests != 'false'
        test('test-libudev-sym', exe)
endif

exe = executable(
        'test-libudev-static-sym',
        test_libudev_sym_c,
        include_directories : includes,
        c_args : '-Wno-deprecated-declarations',
        link_with : [install_libudev_static],
        build_by_default : want_tests != 'false' and static_libudev_pic,
        install : install_tests and static_libudev_pic,
        install_dir : testsdir)
if want_tests != 'false' and static_libudev_pic
        test('test-libudev-static-sym', exe)
endif

############################################################

fuzzer_exes = []

if get_option('tests') != 'false'
foreach tuple : fuzzers
        sources = tuple[0]
        link_with = tuple[1].length() > 0 ? tuple[1] : [libshared]
        dependencies = tuple[2]
        defs = tuple.length() >= 4 ? tuple[3] : []
        incs = tuple.length() >= 5 ? tuple[4] : includes
        link_args = []

        if want_ossfuzz or want_fuzzbuzz
                dependencies += fuzzing_engine
        elif want_libfuzzer
                if fuzzing_engine.found()
                        dependencies += fuzzing_engine
                else
                        link_args += ['-fsanitize=fuzzer']
                endif
        else
                sources += 'src/fuzz/fuzz-main.c'
        endif

        if want_fuzzbuzz
                sources += 'src/fuzz/fuzzer-entry-point.c'
        endif

        name = sources[0].split('/')[-1].split('.')[0]

        fuzzer_exes += executable(
                name,
                sources,
                include_directories : [incs, include_directories('src/fuzz')],
                link_with : link_with,
                dependencies : dependencies,
                c_args : defs,
                link_args: link_args,
                install : false)
endforeach
endif

run_target('fuzzers',
        depends : fuzzer_exes,
        command : ['true'])

############################################################

make_directive_index_py = find_program('tools/make-directive-index.py')
make_man_index_py = find_program('tools/make-man-index.py')
xml_helper_py = find_program('tools/xml_helper.py')
hwdb_update_sh = find_program('tools/meson-hwdb-update.sh')

subdir('units')
subdir('sysctl.d')
subdir('sysusers.d')
subdir('tmpfiles.d')
subdir('presets')
subdir('hwdb')
subdir('network')
subdir('man')
subdir('shell-completion/bash')
subdir('shell-completion/zsh')
subdir('docs/sysvinit')
subdir('docs/var-log')

install_subdir('factory/etc',
               install_dir : factorydir)

install_data('xorg/50-systemd-user.sh',
             install_dir : xinitrcdir)
install_data('modprobe.d/systemd.conf',
             install_dir : modprobedir)
install_data('LICENSE.GPL2',
             'LICENSE.LGPL2.1',
             'NEWS',
             'README',
             'docs/CODING_STYLE.md',
             'docs/DISTRO_PORTING.md',
             'docs/ENVIRONMENT.md',
             'docs/HACKING.md',
             'docs/TRANSIENT-SETTINGS.md',
             'docs/TRANSLATORS.md',
             'docs/UIDS-GIDS.md',
             'src/libsystemd/sd-bus/GVARIANT-SERIALIZATION',
             install_dir : docdir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemdstatedir))
meson.add_install_script('sh', '-c', 'touch $DESTDIR@0@'.format(prefixdir))

############################################################

meson_check_help = find_program('tools/meson-check-help.sh')

foreach exec : public_programs
        name = exec.full_path().split('/')[-1]
        if want_tests != 'false'
                test('check-help-' + name,
                     meson_check_help,
                     args : exec.full_path())
        endif
endforeach

############################################################

check_directives_sh = find_program('tools/check-directives.sh')

if want_tests != 'false'
        test('check-directives',
             check_directives_sh,
             args : project_source_root)
endif

############################################################

# Enable tests for all supported sanitizers
foreach tuple : sanitizers
        sanitizer = tuple[0]
        build = tuple[1]

        if cc.has_link_argument('-fsanitize=@0@'.format(sanitizer))
                prev = ''
                foreach p : fuzz_regression_tests
                        b = p.split('/')[-2]
                        c = p.split('/')[-1]

                        name = '@0@:@1@'.format(b, sanitizer)

                        if name != prev
                                if want_tests == 'false'
                                        message('Not compiling @0@ because tests is set to false'.format(name))
                                elif slow_tests
                                        exe = custom_target(
                                                name,
                                                output : name,
                                                depends : build,
                                                command : [env, 'ln', '-fs',
                                                           join_paths(build.full_path(), b),
                                                           '@OUTPUT@'],
                                                build_by_default : true)
                                else
                                        message('Not compiling @0@ because slow-tests is set to false'.format(name))
                                endif
                        endif
                        prev = name

                        if want_tests != 'false' and slow_tests
                                test('@0@:@1@:@2@'.format(b, c, sanitizer),
                                     env,
                                     args : [exe.full_path(),
                                             join_paths(project_source_root, p)])
                        endif
                endforeach
        endif
endforeach


############################################################

if git.found()
        all_files = run_command(
                git,
                ['--git-dir=@0@/.git'.format(project_source_root),
                 'ls-files',
                 ':/*.[ch]'])
        all_files = files(all_files.stdout().split())

        custom_target(
                'tags',
                output : 'tags',
                command : [env, 'etags', '-o', '@0@/TAGS'.format(project_source_root)] + all_files)
        run_target(
                'ctags',
                command : [env, 'ctags', '-o', '@0@/tags'.format(project_source_root)] + all_files)
endif

if git.found()
        meson_git_contrib_sh = find_program('tools/meson-git-contrib.sh')
        run_target(
                'git-contrib',
                command : [meson_git_contrib_sh])
endif

if git.found()
        git_head = run_command(
                git,
                ['--git-dir=@0@/.git'.format(project_source_root),
                 'rev-parse', 'HEAD']).stdout().strip()
        git_head_short = run_command(
                git,
                ['--git-dir=@0@/.git'.format(project_source_root),
                 'rev-parse', '--short=7', 'HEAD']).stdout().strip()

        run_target(
                'git-snapshot',
                command : ['git', 'archive',
                           '-o', '@0@/systemd-@1@.tar.gz'.format(project_source_root,
                                                                 git_head_short),
                           '--prefix', 'systemd-@0@/'.format(git_head),
                           'HEAD'])
endif

############################################################

meson_check_api_docs_sh = find_program('tools/meson-check-api-docs.sh')
run_target(
        'check-api-docs',
        depends : [man, libsystemd, libudev],
        command : [meson_check_api_docs_sh, libsystemd.full_path(), libudev.full_path()])

############################################################

status = [
        '@0@ @1@'.format(meson.project_name(), meson.project_version()),

        'split /usr:                        @0@'.format(split_usr),
        'split bin-sbin:                    @0@'.format(split_bin),
        'prefix directory:                  @0@'.format(prefixdir),
        'rootprefix directory:              @0@'.format(rootprefixdir),
        'sysconf directory:                 @0@'.format(sysconfdir),
        'include directory:                 @0@'.format(includedir),
        'lib directory:                     @0@'.format(libdir),
        'rootlib directory:                 @0@'.format(rootlibdir),
        'SysV init scripts:                 @0@'.format(sysvinit_path),
        'SysV rc?.d directories:            @0@'.format(sysvrcnd_path),
        'PAM modules directory:             @0@'.format(pamlibdir),
        'PAM configuration directory:       @0@'.format(pamconfdir),
        'RPM macros directory:              @0@'.format(rpmmacrosdir),
        'modprobe.d directory:              @0@'.format(modprobedir),
        'D-Bus policy directory:            @0@'.format(dbuspolicydir),
        'D-Bus session directory:           @0@'.format(dbussessionservicedir),
        'D-Bus system directory:            @0@'.format(dbussystemservicedir),
        'bash completions directory:        @0@'.format(bashcompletiondir),
        'zsh completions directory:         @0@'.format(zshcompletiondir),
        'extra start script:                @0@'.format(get_option('rc-local')),
        'debug shell:                       @0@ @ @1@'.format(get_option('debug-shell'),
                                                              get_option('debug-tty')),
        'TTY GID:                           @0@'.format(tty_gid),
        'users GID:                         @0@'.format(substs.get('USERS_GID')),
        'maximum system UID:                @0@'.format(system_uid_max),
        'maximum system GID:                @0@'.format(system_gid_max),
        'minimum dynamic UID:               @0@'.format(dynamic_uid_min),
        'maximum dynamic UID:               @0@'.format(dynamic_uid_max),
        'minimum container UID base:        @0@'.format(container_uid_base_min),
        'maximum container UID base:        @0@'.format(container_uid_base_max),
        '/dev/kvm access mode:              @0@'.format(get_option('dev-kvm-mode')),
        'render group access mode:          @0@'.format(get_option('group-render-mode')),
        'certificate root directory:        @0@'.format(get_option('certificate-root')),
        'support URL:                       @0@'.format(support_url),
        'nobody user name:                  @0@'.format(nobody_user),
        'nobody group name:                 @0@'.format(nobody_group),
        'fallback hostname:                 @0@'.format(get_option('fallback-hostname')),
        'symbolic gateway hostnames:        @0@'.format(', '.join(gateway_hostnames)),

        'default DNSSEC mode:               @0@'.format(default_dnssec),
        'default DNS-over-TLS mode:         @0@'.format(default_dns_over_tls),
        'default cgroup hierarchy:          @0@'.format(default_hierarchy),
        'default net.naming-scheme setting: @0@'.format(default_net_naming_scheme),
        'default KillUserProcesses setting: @0@'.format(kill_user_processes),
        'default locale:                    @0@'.format(default_locale)]

alt_dns_servers = '\n                                            '.join(dns_servers.split(' '))
alt_ntp_servers = '\n                                            '.join(ntp_servers.split(' '))
status += [
        'default DNS servers:               @0@'.format(alt_dns_servers),
        'default NTP servers:               @0@'.format(alt_ntp_servers)]

alt_time_epoch = run_command('date', '-Is', '-u', '-d',
                             '@@0@'.format(time_epoch)).stdout().strip()
status += [
        'time epoch:                        @0@ (@1@)'.format(time_epoch, alt_time_epoch)]

status += [
        'static libsystemd:                 @0@'.format(static_libsystemd),
        'static libudev:                    @0@'.format(static_libudev)]

# TODO:
# CFLAGS:   ${OUR_CFLAGS} ${CFLAGS}
# CPPFLAGS: ${OUR_CPPFLAGS} ${CPPFLAGS}
# LDFLAGS:  ${OUR_LDFLAGS} ${LDFLAGS}

if conf.get('ENABLE_EFI') == 1
        status += 'efi arch:                          @0@'.format(efi_arch)

        if have_gnu_efi
                status += [
                        'EFI machine type:                  @0@'.format(EFI_MACHINE_TYPE_NAME),
                        'EFI CC                             @0@'.format(' '.join(efi_cc)),
                        'EFI lib directory:                 @0@'.format(efi_libdir),
                        'EFI lds directory:                 @0@'.format(efi_ldsdir),
                        'EFI include directory:             @0@'.format(efi_incdir)]
        endif
endif

found = []
missing = []

foreach tuple : [
        ['libcryptsetup'],
        ['PAM'],
        ['AUDIT'],
        ['IMA'],
        ['AppArmor'],
        ['SELinux'],
        ['SECCOMP'],
        ['SMACK'],
        ['zlib'],
        ['xz'],
        ['lz4'],
        ['bzip2'],
        ['ACL'],
        ['gcrypt'],
        ['qrencode'],
        ['microhttpd'],
        ['gnutls'],
        ['openssl'],
        ['libcurl'],
        ['idn'],
        ['libidn2'],
        ['libidn'],
        ['libiptc'],
        ['elfutils'],
        ['binfmt'],
        ['vconsole'],
        ['quotacheck'],
        ['tmpfiles'],
        ['environment.d'],
        ['sysusers'],
        ['firstboot'],
        ['randomseed'],
        ['backlight'],
        ['rfkill'],
        ['logind'],
        ['machined'],
        ['portabled'],
        ['importd'],
        ['hostnamed'],
        ['timedated'],
        ['timesyncd'],
        ['localed'],
        ['networkd'],
        ['resolve'],
        ['DNS-over-TLS(gnutls)',  conf.get('DNS_OVER_TLS_USE_GNUTLS') == 1],
        ['DNS-over-TLS(openssl)', conf.get('DNS_OVER_TLS_USE_OPENSSL') == 1],
        ['coredump'],
        ['pstore'],
        ['polkit'],
        ['legacy pkla',      install_polkit_pkla],
        ['efi'],
        ['gnu-efi',          have_gnu_efi],
        ['kmod'],
        ['xkbcommon'],
        ['pcre2'],
        ['blkid'],
        ['dbus'],
        ['glib'],
        ['nss-myhostname'],
        ['nss-mymachines'],
        ['nss-resolve'],
        ['nss-systemd'],
        ['hwdb'],
        ['tpm'],
        ['man pages',        want_man],
        ['html pages',       want_html],
        ['man page indices', want_man and have_lxml],
        ['SysV compat'],
        ['utmp'],
        ['ldconfig'],
        ['hibernate'],
        ['adm group',        get_option('adm-group')],
        ['wheel group',      get_option('wheel-group')],
        ['gshadow'],
        ['debug hashmap'],
        ['debug mmap cache'],
        ['debug siphash'],
        ['valgrind',         conf.get('VALGRIND') == 1],
        ['trace logging',    conf.get('LOG_TRACE') == 1],
        ['link-udev-shared',      get_option('link-udev-shared')],
        ['link-systemctl-shared', get_option('link-systemctl-shared')],
]

        if tuple.length() >= 2
                cond = tuple[1]
        else
                ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
                ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
                cond = conf.get(ident1, 0) == 1 or conf.get(ident2, 0) == 1
        endif
        if cond
                found += tuple[0]
        else
                missing += tuple[0]
        endif
endforeach

status += [
        '',
        'enabled features: @0@'.format(', '.join(found)),
        '',
        'disabled features: @0@'.format(', '.join(missing)),
        '']
message('\n         '.join(status))

if rootprefixdir != rootprefix_default
        warning('\n' +
                'Note that the installation prefix was changed to "@0@".\n'.format(rootprefixdir) +
                'systemd used fixed names for unit file directories and other paths, so anything\n' +
                'except the default ("@0@") is strongly discouraged.'.format(rootprefix_default))
endif

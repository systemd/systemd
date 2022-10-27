# SPDX-License-Identifier: LGPL-2.1-or-later

project('systemd', 'c',
        version : '252',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
                'warning_level=2',
        ],
        meson_version : '>= 0.53.2',
       )

libsystemd_version = '0.35.0'
libudev_version = '1.7.5'

conf = configuration_data()
conf.set_quoted('PROJECT_URL', 'https://systemd.io/')
conf.set('PROJECT_VERSION',    meson.project_version(),
         description : 'Numerical project version (used where a simple number is expected)')

# This is to be used instead of meson.source_root(), as the latter will return
# the wrong result when systemd is being built as a meson subproject
project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()
relative_source_path = run_command('realpath',
                                   '--relative-to=@0@'.format(project_build_root),
                                   project_source_root,
                                   check : true).stdout().strip()
conf.set_quoted('RELATIVE_SOURCE_PATH', relative_source_path)

conf.set10('BUILD_MODE_DEVELOPER', get_option('mode') == 'developer',
           description : 'tailor build to development or release builds')
verification = get_option('log-message-verification')
if verification == 'auto'
        verification = conf.get('BUILD_MODE_DEVELOPER') == 1
else
        verification = verification == 'true'
endif
conf.set10('LOG_MESSAGE_VERIFICATION', verification)

want_ossfuzz = get_option('oss-fuzz')
want_libfuzzer = get_option('llvm-fuzz')
if want_ossfuzz and want_libfuzzer
        error('only one of oss-fuzz or llvm-fuzz can be specified')
endif

skip_deps = want_ossfuzz or get_option('skip-deps')
fuzzer_build = want_ossfuzz or want_libfuzzer

# If we're building *not* for actual fuzzing, allow input samples of any size
# (for testing and for reproduction of issues discovered with previously-higher
# limits).
conf.set10('FUZZ_USE_SIZE_LIMIT', fuzzer_build)

# Create a title-less summary section early, so it ends up first in the output.
# More items are added later after they have been detected.
summary({'build mode' : get_option('mode')})

#####################################################################

# Try to install the git pre-commit hook
add_git_hook_sh = find_program('tools/add-git-hook.sh', required : false)
if add_git_hook_sh.found()
        git_hook = run_command(add_git_hook_sh, check : false)
        if git_hook.returncode() == 0
                message(git_hook.stdout().strip())
        endif
endif

#####################################################################

fs = import('fs')
if get_option('split-usr') == 'auto'
        split_usr = not fs.is_symlink('/bin')
else
        split_usr = get_option('split-usr') == 'true'
endif
if split_usr
        warning('\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n'
                + '                    split-usr mode is going to be removed\n' +
                '\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
endif
conf.set10('HAVE_SPLIT_USR', split_usr,
           description : '/usr/bin and /bin directories are separate')

if get_option('split-bin') == 'auto'
        split_bin = not fs.is_symlink('/usr/sbin')
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

have_standalone_binaries = get_option('standalone-binaries')

sysvinit_path = get_option('sysvinit-path')
sysvrcnd_path = get_option('sysvrcnd-path')
conf.set10('HAVE_SYSV_COMPAT', sysvinit_path != '' and sysvrcnd_path != '',
           description : 'SysV init scripts and rcN.d links are supported')
conf.set10('CREATE_LOG_DIRS', get_option('create-log-dirs'))

if get_option('hibernate') and not get_option('initrd')
        error('hibernate depends on initrd')
endif

conf.set10('BUMP_PROC_SYS_FS_FILE_MAX', get_option('bump-proc-sys-fs-file-max'))
conf.set10('BUMP_PROC_SYS_FS_NR_OPEN',  get_option('bump-proc-sys-fs-nr-open'))
conf.set('HIGH_RLIMIT_NOFILE',          512*1024)

# Meson ignores the preceding arguments when joining paths if an absolute
# component is encountered, so this should canonicalize various paths when they
# are absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
if prefixdir != rootprefixdir and rootprefixdir != '/' and not prefixdir.strip('/').startswith(rootprefixdir.strip('/') + '/')
        error('Prefix is not below root prefix (now rootprefix=@0@ prefix=@1@)'.format(
                rootprefixdir, prefixdir))
endif

bindir = prefixdir / get_option('bindir')
libdir = prefixdir / get_option('libdir')
sysconfdir = prefixdir / get_option('sysconfdir')
includedir = prefixdir / get_option('includedir')
datadir = prefixdir / get_option('datadir')
localstatedir = '/' / get_option('localstatedir')

rootbindir = rootprefixdir / 'bin'
rootsbindir = rootprefixdir / (split_bin ? 'sbin' : 'bin')
rootlibexecdir = rootprefixdir / 'lib/systemd'

rootlibdir = get_option('rootlibdir')
if rootlibdir == ''
        # This will be a relative path if libdir is in prefix.
        rootlibdir = get_option('libdir')
endif
if not rootlibdir.startswith('/')
        # If we have a relative path, add rootprefixdir to the front.
        rootlibdir = rootprefixdir / rootlibdir
endif
rootpkglibdir = rootlibdir / 'systemd'

install_sysconfdir = get_option('install-sysconfdir') != 'false'
install_sysconfdir_samples = get_option('install-sysconfdir') == 'true'
# Dirs of external packages
pkgconfigdatadir = get_option('pkgconfigdatadir') != '' ? get_option('pkgconfigdatadir') : datadir / 'pkgconfig'
pkgconfiglibdir = get_option('pkgconfiglibdir') != '' ? get_option('pkgconfiglibdir') : libdir / 'pkgconfig'
polkitpolicydir = datadir / 'polkit-1/actions'
polkitrulesdir = datadir / 'polkit-1/rules.d'
polkitpkladir = localstatedir / 'lib/polkit-1/localauthority/10-vendor.d'
xinitrcdir = get_option('xinitrcdir') != '' ? get_option('xinitrcdir') : sysconfdir / 'X11/xinit/xinitrc.d'
rpmmacrosdir = get_option('rpmmacrosdir')
if rpmmacrosdir != 'no'
        rpmmacrosdir = prefixdir / rpmmacrosdir
endif
modprobedir = rootprefixdir / 'lib/modprobe.d'

# Our own paths
pkgdatadir = datadir / 'systemd'
environmentdir = prefixdir / 'lib/environment.d'
pkgsysconfdir = sysconfdir / 'systemd'
userunitdir = prefixdir / 'lib/systemd/user'
userpresetdir = prefixdir / 'lib/systemd/user-preset'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'
usertmpfilesdir = prefixdir / 'share/user-tmpfiles.d'
sysusersdir = prefixdir / 'lib/sysusers.d'
sysctldir = prefixdir / 'lib/sysctl.d'
binfmtdir = prefixdir / 'lib/binfmt.d'
modulesloaddir = prefixdir / 'lib/modules-load.d'
networkdir = rootprefixdir / 'lib/systemd/network'
pkgincludedir = includedir / 'systemd'
systemgeneratordir = rootlibexecdir / 'system-generators'
usergeneratordir = prefixdir / 'lib/systemd/user-generators'
systemenvgeneratordir = prefixdir / 'lib/systemd/system-environment-generators'
userenvgeneratordir = prefixdir / 'lib/systemd/user-environment-generators'
systemshutdowndir = rootlibexecdir / 'system-shutdown'
systemsleepdir = rootlibexecdir / 'system-sleep'
systemunitdir = rootprefixdir / 'lib/systemd/system'
systempresetdir = rootprefixdir / 'lib/systemd/system-preset'
udevlibexecdir = rootprefixdir / 'lib/udev'
udevrulesdir = udevlibexecdir / 'rules.d'
udevhwdbdir = udevlibexecdir / 'hwdb.d'
catalogdir = prefixdir / 'lib/systemd/catalog'
kerneldir = prefixdir / 'lib/kernel'
kernelinstalldir = kerneldir / 'install.d'
factorydir = datadir / 'factory'
bootlibdir = prefixdir / 'lib/systemd/boot/efi'
testsdir = prefixdir / 'lib/systemd/tests'
systemdstatedir = localstatedir / 'lib/systemd'
catalogstatedir = systemdstatedir / 'catalog'
randomseeddir = localstatedir / 'lib/systemd'
profiledir = rootlibexecdir / 'portable' / 'profile'
ntpservicelistdir = rootprefixdir / 'lib/systemd/ntp-units.d'

docdir = get_option('docdir')
if docdir == ''
        docdir = datadir / 'doc/systemd'
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = rootlibdir / 'security'
endif

pamconfdir = get_option('pamconfdir')
if pamconfdir == ''
        pamconfdir = prefixdir / 'lib/pam.d'
endif

libcryptsetup_plugins_dir = get_option('libcryptsetup-plugins-dir')
if libcryptsetup_plugins_dir == ''
        libcryptsetup_plugins_dir = rootlibdir / 'cryptsetup'
endif

memory_accounting_default = get_option('memory-accounting-default')
status_unit_format_default = get_option('status-unit-format-default')
if status_unit_format_default == 'auto'
        status_unit_format_default = conf.get('BUILD_MODE_DEVELOPER') == 1 ? 'name' : 'description'
endif

conf.set_quoted('BINFMT_DIR',                                 binfmtdir)
conf.set_quoted('BOOTLIBDIR',                                 bootlibdir)
conf.set_quoted('CATALOG_DATABASE',                           catalogstatedir / 'database')
conf.set_quoted('CERTIFICATE_ROOT',                           get_option('certificate-root'))
conf.set_quoted('DOC_DIR',                                    docdir)
conf.set_quoted('DOCUMENT_ROOT',                              pkgdatadir / 'gatewayd')
conf.set_quoted('ENVIRONMENT_DIR',                            environmentdir)
conf.set_quoted('INCLUDE_DIR',                                includedir)
conf.set_quoted('LIBDIR',                                     libdir)
conf.set_quoted('MODPROBE_DIR',                               modprobedir)
conf.set_quoted('MODULESLOAD_DIR',                            modulesloaddir)
conf.set_quoted('PKGSYSCONFDIR',                              pkgsysconfdir)
conf.set_quoted('POLKIT_AGENT_BINARY_PATH',                   bindir / 'pkttyagent')
conf.set_quoted('PREFIX',                                     prefixdir)
conf.set_quoted('RANDOM_SEED',                                randomseeddir / 'random-seed')
conf.set_quoted('RANDOM_SEED_DIR',                            randomseeddir)
conf.set_quoted('RC_LOCAL_PATH',                              get_option('rc-local'))
conf.set_quoted('ROOTBINDIR',                                 rootbindir)
conf.set_quoted('ROOTLIBDIR',                                 rootlibdir)
conf.set_quoted('ROOTLIBEXECDIR',                             rootlibexecdir)
conf.set_quoted('ROOTPREFIX',                                 rootprefixdir)
conf.set_quoted('ROOTPREFIX_NOSLASH',                         rootprefixdir_noslash)
conf.set_quoted('SYSCONF_DIR',                                sysconfdir)
conf.set_quoted('SYSCTL_DIR',                                 sysctldir)
conf.set_quoted('SYSTEMCTL_BINARY_PATH',                      rootbindir / 'systemctl')
conf.set_quoted('SYSTEMD_BINARY_PATH',                        rootlibexecdir / 'systemd')
conf.set_quoted('SYSTEMD_CATALOG_DIR',                        catalogdir)
conf.set_quoted('SYSTEMD_CGROUPS_AGENT_PATH',                 rootlibexecdir / 'systemd-cgroups-agent')
conf.set_quoted('SYSTEMD_CRYPTSETUP_PATH',                    rootlibexecdir / 'systemd-cryptsetup')
conf.set_quoted('SYSTEMD_EXPORT_PATH',                        rootlibexecdir / 'systemd-export')
conf.set_quoted('SYSTEMD_FSCK_PATH',                          rootlibexecdir / 'systemd-fsck')
conf.set_quoted('SYSTEMD_GROWFS_PATH',                        rootlibexecdir / 'systemd-growfs')
conf.set_quoted('SYSTEMD_HOMEWORK_PATH',                      rootlibexecdir / 'systemd-homework')
conf.set_quoted('SYSTEMD_IMPORT_FS_PATH',                     rootlibexecdir / 'systemd-import-fs')
conf.set_quoted('SYSTEMD_IMPORT_PATH',                        rootlibexecdir / 'systemd-import')
conf.set_quoted('SYSTEMD_INTEGRITYSETUP_PATH',                rootlibexecdir / 'systemd-integritysetup')
conf.set_quoted('SYSTEMD_KBD_MODEL_MAP',                      pkgdatadir / 'kbd-model-map')
conf.set_quoted('SYSTEMD_LANGUAGE_FALLBACK_MAP',              pkgdatadir / 'language-fallback-map')
conf.set_quoted('SYSTEMD_MAKEFS_PATH',                        rootlibexecdir / 'systemd-makefs')
conf.set_quoted('SYSTEMD_PULL_PATH',                          rootlibexecdir / 'systemd-pull')
conf.set_quoted('SYSTEMD_SHUTDOWN_BINARY_PATH',               rootlibexecdir / 'systemd-shutdown')
conf.set_quoted('SYSTEMD_TEST_DATA',                          testsdir / 'testdata')
conf.set_quoted('SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH', rootbindir / 'systemd-tty-ask-password-agent')
conf.set_quoted('SYSTEMD_UPDATE_HELPER_PATH',                 rootlibexecdir / 'systemd-update-helper')
conf.set_quoted('SYSTEMD_USERWORK_PATH',                      rootlibexecdir / 'systemd-userwork')
conf.set_quoted('SYSTEMD_VERITYSETUP_PATH',                   rootlibexecdir / 'systemd-veritysetup')
conf.set_quoted('SYSTEM_CONFIG_UNIT_DIR',                     pkgsysconfdir / 'system')
conf.set_quoted('SYSTEM_DATA_UNIT_DIR',                       systemunitdir)
conf.set_quoted('SYSTEM_ENV_GENERATOR_DIR',                   systemenvgeneratordir)
conf.set_quoted('SYSTEM_GENERATOR_DIR',                       systemgeneratordir)
conf.set_quoted('SYSTEM_PRESET_DIR',                          systempresetdir)
conf.set_quoted('SYSTEM_SHUTDOWN_PATH',                       systemshutdowndir)
conf.set_quoted('SYSTEM_SLEEP_PATH',                          systemsleepdir)
conf.set_quoted('SYSTEM_SYSVINIT_PATH',                       sysvinit_path)
conf.set_quoted('SYSTEM_SYSVRCND_PATH',                       sysvrcnd_path)
conf.set_quoted('SYSUSERS_DIR',                               sysusersdir)
conf.set_quoted('TMPFILES_DIR',                               tmpfilesdir)
conf.set_quoted('USER_TMPFILES_DIR',                          usertmpfilesdir)
conf.set_quoted('UDEVLIBEXECDIR',                             udevlibexecdir)
conf.set_quoted('UDEV_HWDB_DIR',                              udevhwdbdir)
conf.set_quoted('UDEV_RULES_DIR',                             udevrulesdir)
conf.set_quoted('UPDATE_HELPER_USER_TIMEOUT',                 get_option('update-helper-user-timeout'))
conf.set_quoted('USER_CONFIG_UNIT_DIR',                       pkgsysconfdir / 'user')
conf.set_quoted('USER_DATA_UNIT_DIR',                         userunitdir)
conf.set_quoted('USER_ENV_GENERATOR_DIR',                     userenvgeneratordir)
conf.set_quoted('USER_GENERATOR_DIR',                         usergeneratordir)
conf.set_quoted('USER_KEYRING_PATH',                          pkgsysconfdir / 'import-pubring.gpg')
conf.set_quoted('USER_PRESET_DIR',                            userpresetdir)
conf.set_quoted('VENDOR_KEYRING_PATH',                        rootlibexecdir / 'import-pubring.gpg')

conf.set('ANSI_OK_COLOR',                                     'ANSI_' + get_option('ok-color').underscorify().to_upper())
conf.set10('ENABLE_URLIFY',                                   get_option('urlify'))
conf.set10('ENABLE_FEXECVE',                                  get_option('fexecve'))
conf.set10('MEMORY_ACCOUNTING_DEFAULT',                       memory_accounting_default)
conf.set('STATUS_UNIT_FORMAT_DEFAULT',                        'STATUS_UNIT_FORMAT_' + status_unit_format_default.to_upper())
conf.set_quoted('STATUS_UNIT_FORMAT_DEFAULT_STR',             status_unit_format_default)

conf.set10('FIRST_BOOT_FULL_PRESET',                          get_option('first-boot-full-preset'))

conf.set10('EFI_TPM_PCR_COMPAT',                              get_option('efi-tpm-pcr-compat'))

#####################################################################

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')
meson_build_sh = find_program('tools/meson-build.sh')

want_tests = get_option('tests')
slow_tests = want_tests != 'false' and get_option('slow-tests')
fuzz_tests = want_tests != 'false' and get_option('fuzz-tests')
install_tests = get_option('install-tests')

if add_languages('cpp', required : fuzzer_build)
        #  Used only for tests
        cxx = meson.get_compiler('cpp')
        cxx_cmd = ' '.join(cxx.cmd_array())
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
endif

# Those generate many false positives, and we do not want to change the code to
# avoid them.
basic_disabled_warnings = [
        '-Wno-missing-field-initializers',
        '-Wno-unused-parameter',
]

possible_common_cc_flags = [
        '-Wdate-time',
        '-Wendif-labels',
        '-Werror=format=2',
        '-Werror=format-signedness',
        '-Werror=implicit-function-declaration',
        '-Werror=incompatible-pointer-types',
        '-Werror=int-conversion',
        '-Werror=overflow',
        '-Werror=override-init',
        '-Werror=return-type',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Werror=undef',
        '-Wfloat-equal',
        # gperf prevents us from enabling this because it does not emit fallthrough
        # attribute with clang.
        #'-Wimplicit-fallthrough',
        '-Wimplicit-fallthrough=5',
        '-Winit-self',
        '-Wlogical-op',
        '-Wmissing-include-dirs',
        '-Wmissing-noreturn',
        '-Wnested-externs',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Wredundant-decls',
        '-Wshadow',
        '-Wstrict-aliasing=2',
        '-Wstrict-prototypes',
        '-Wsuggest-attribute=noreturn',
        '-Wunused-function',
        '-Wwrite-strings',

        # negative arguments are correctly detected starting with meson 0.46.
        '-Wno-error=#warnings',  # clang
        '-Wno-string-plus-int',  # clang
]

c_args = get_option('c_args')

# Our json library does not support -ffinite-math-only, which is enabled by -Ofast or -ffast-math.
if (('-Ofast' in c_args or '-ffast-math' in c_args or '-ffinite-math-only' in c_args) and '-fno-finite-math-only' not in c_args)
        error('-Ofast, -ffast-math, or -ffinite-math-only is specified in c_args.')
endif

# Disable -Wmaybe-uninitialized when compiling with -Os/-O1/-O3/etc. There are
# too many false positives with gcc >= 8. Effectively, we only test with -O0
# and -O2; this should be enough to catch most important cases without too much
# busywork. See https://github.com/systemd/systemd/pull/19226.
if cc.get_id() == 'gcc' and (not '02'.contains(get_option('optimization')) or
                             cc.version().version_compare('<10') or
                             '-Os' in c_args or
                             '-O1' in c_args or
                             '-O3' in c_args or
                             '-Og' in c_args)
        possible_common_cc_flags += '-Wno-maybe-uninitialized'
endif

# Disable -Wno-unused-result with gcc, see
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425.
if cc.get_id() == 'gcc'
        possible_common_cc_flags += '-Wno-unused-result'
endif

# --as-needed and --no-undefined are provided by meson by default,
# run 'meson configure' to see what is enabled
possible_link_flags = [
        '-Wl,--fatal-warnings',
        '-Wl,-z,now',
        '-Wl,-z,relro',
        '-fstack-protector',
]

if get_option('b_sanitize') == 'none'
        possible_link_flags += '-Wl,--warn-common'
endif

if cc.get_id() == 'clang'
        possible_common_cc_flags += [
                '-Wno-typedef-redefinition',
                '-Wno-gnu-variable-sized-type-not-at-end',
        ]
endif

if get_option('mode') == 'release'
        # We could enable 'pattern' for developer mode, but that can interfere with
        # valgrind and sanitizer builds. Also, clang does not zero-initialize unions,
        # breaking some of our code (https://reviews.llvm.org/D68115).
        possible_common_cc_flags += '-ftrivial-auto-var-init=zero'
endif

possible_cc_flags = possible_common_cc_flags + [
        '-Werror=missing-declarations',
        '-Werror=missing-prototypes',
        '-fdiagnostics-show-option',
        '-fno-common',
        '-fno-strict-aliasing',
        '-fstack-protector',
        '-fstack-protector-strong',
        '-fvisibility=hidden',
        '--param=ssp-buffer-size=4',
]

if get_option('buildtype') != 'debug'
        possible_cc_flags += [
                '-ffunction-sections',
                '-fdata-sections',
        ]

        possible_link_flags += '-Wl,--gc-sections'
endif

if get_option('mode') == 'developer'
        possible_cc_flags += '-fno-omit-frame-pointer'
endif

add_project_arguments(cc.get_supported_arguments(basic_disabled_warnings), language : 'c')
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')
add_project_link_arguments(cc.get_supported_link_arguments(possible_link_flags), language : 'c')

have = cc.has_argument('-Wzero-length-bounds')
conf.set10('HAVE_ZERO_LENGTH_BOUNDS', have)

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

if cxx_cmd != ''
        add_project_arguments(cxx.get_supported_arguments(basic_disabled_warnings), language : 'cpp')
endif

cpp = ' '.join(cc.cmd_array()) + ' -E'

has_wstringop_truncation = cc.has_argument('-Wstringop-truncation')

#####################################################################
# compilation result tests

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)
conf.set10('HAVE_WSTRINGOP_TRUNCATION', has_wstringop_truncation)

conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))
conf.set('SIZEOF_TIMEX_MEMBER', cc.sizeof('typeof(((struct timex *)0)->freq)', prefix : '#include <sys/timex.h>'))

decl_headers = '''
#include <uchar.h>
#include <sys/mount.h>
#include <sys/stat.h>
'''

foreach decl : ['char16_t',
                'char32_t',
                'struct mount_attr',
                'struct statx',
               ]

        # We get -1 if the size cannot be determined
        have = cc.sizeof(decl, prefix : decl_headers, args : '-D_GNU_SOURCE') > 0

        if decl == 'struct mount_attr'
                if have
                        want_linux_fs_h = false
                else
                        have = cc.sizeof(decl,
                                         prefix : decl_headers + '#include <linux/fs.h>',
                                         args : '-D_GNU_SOURCE') > 0
                        want_linux_fs_h = have
                endif
        endif

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
conf.set10('WANT_LINUX_FS_H', want_linux_fs_h)

foreach ident : ['secure_getenv', '__secure_getenv']
        conf.set10('HAVE_' + ident.to_upper(), cc.has_function(ident))
endforeach

foreach ident : [
        ['memfd_create',      '''#include <sys/mman.h>'''],
        ['gettid',            '''#include <sys/types.h>
                                 #include <unistd.h>'''],
        ['pivot_root',        '''#include <stdlib.h>
                                 #include <unistd.h>'''],     # no known header declares pivot_root
        ['ioprio_get',        '''#include <sched.h>'''],      # no known header declares ioprio_get
        ['ioprio_set',        '''#include <sched.h>'''],      # no known header declares ioprio_set
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
        ['reallocarray',      '''#include <stdlib.h>'''],
        ['set_mempolicy',     '''#include <stdlib.h>
                                 #include <unistd.h>'''],
        ['get_mempolicy',     '''#include <stdlib.h>
                                 #include <unistd.h>'''],
        ['pidfd_send_signal', '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['pidfd_open',        '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['rt_sigqueueinfo',   '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['mallinfo',          '''#include <malloc.h>'''],
        ['mallinfo2',         '''#include <malloc.h>'''],
        ['execveat',          '''#include <unistd.h>'''],
        ['close_range',       '''#include <unistd.h>'''],
        ['epoll_pwait2',      '''#include <sys/epoll.h>'''],
        ['mount_setattr',     '''#include <sys/mount.h>'''],
        ['move_mount',        '''#include <sys/mount.h>'''],
        ['open_tree',         '''#include <sys/mount.h>'''],
        ['fsopen',            '''#include <sys/mount.h>'''],
        ['fsconfig',          '''#include <sys/mount.h>'''],
        ['getdents64',        '''#include <dirent.h>'''],
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

version_tag = get_option('version-tag')
if version_tag != ''
        vcs_data = configuration_data()
        vcs_data.set('VCS_TAG', version_tag)
        version_h = configure_file(configuration : vcs_data,
                                   input : 'src/version/version.h.in',
                                   output : 'version.h')
else
        vcs_tagger = [
                project_source_root + '/tools/meson-vcs-tag.sh',
                project_source_root,
                meson.project_version()]

        version_h = vcs_tag(
                input : 'src/version/version.h.in',
                output : 'version.h',
                command: vcs_tagger)
endif

versiondep = declare_dependency(sources: version_h)

shared_lib_tag = get_option('shared-lib-tag')
if shared_lib_tag == ''
        shared_lib_tag = meson.project_version()
endif

sh = find_program('sh')
echo = find_program('echo')
sed = find_program('sed')
awk = find_program('awk')
stat = find_program('stat')
ln = find_program('ln')
git = find_program('git', required : false)
env = find_program('env')
perl = find_program('perl', required : false)
rsync = find_program('rsync', required : false)
meson_make_symlink = project_source_root + '/tools/meson-make-symlink.sh'

mkdir_p = 'mkdir -p $DESTDIR/@0@'

# If -Dxxx-path option is found, use that. Otherwise, check in $PATH,
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
endforeach

conf.set_quoted('TELINIT', get_option('telinit-path'))

if run_command(ln, '--relative', '--help', check : false).returncode() != 0
        error('ln does not support --relative (added in coreutils 8.16)')
endif

############################################################

python = find_program('python3')
if run_command(python, '-c', 'import jinja2', check : false).returncode() != 0
        error('python3 jinja2 missing')
endif

############################################################

gperf = find_program('gperf')

gperf_test_format = '''
#include <string.h>
const char * in_word_set(const char *, @0@);
@1@
'''
gperf_snippet = run_command(sh, '-c', 'echo foo,bar | "$1" -L ANSI-C', '_', gperf,
                            check : true)
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
                  'linux/time_types.h',
                  'sys/sdt.h',
                 ]

        conf.set10('HAVE_' + header.underscorify().to_upper(),
                   cc.has_header(header))
endforeach

############################################################

fallback_hostname = get_option('fallback-hostname')
if fallback_hostname == '' or fallback_hostname[0] == '.' or fallback_hostname[0] == '-'
        error('Invalid fallback-hostname configuration')
        # A more extensive test is done in test-hostname-util. Let's catch
        # the most obvious errors here so we don't fail with an assert later.
endif
conf.set_quoted('FALLBACK_HOSTNAME', fallback_hostname)

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

extra_net_naming_schemes = []
extra_net_naming_map = []
foreach scheme: get_option('extra-net-naming-schemes').split(',')
        if scheme != ''
                name = scheme.split('=')[0]
                value = scheme.split('=')[1]
                NAME = name.underscorify().to_upper()
                VALUE = []
                foreach field: value.split('+')
                        VALUE += 'NAMING_' + field.underscorify().to_upper()
                endforeach
                extra_net_naming_schemes += 'NAMING_@0@ = @1@,'.format(NAME, '|'.join(VALUE))
                extra_net_naming_map += '{ "@0@", NAMING_@1@ },'.format(name, NAME)
        endif
endforeach
conf.set('EXTRA_NET_NAMING_SCHEMES', ' '.join(extra_net_naming_schemes))
conf.set('EXTRA_NET_NAMING_MAP', ' '.join(extra_net_naming_map))

default_net_naming_scheme = get_option('default-net-naming-scheme')
conf.set_quoted('DEFAULT_NET_NAMING_SCHEME', default_net_naming_scheme)
if default_net_naming_scheme != 'latest'
        conf.set('_DEFAULT_NET_NAMING_SCHEME_TEST',
                 'NAMING_' + default_net_naming_scheme.underscorify().to_upper())
endif

time_epoch = get_option('time-epoch')
if time_epoch <= 0
        time_epoch = run_command(sh, '-c', 'echo "$SOURCE_DATE_EPOCH"', check : true).stdout().strip()
        if time_epoch == '' and git.found() and fs.exists('.git')
                # If we're in a git repository, use the creation time of the latest git tag.
                latest_tag = run_command(git, 'describe', '--abbrev=0', '--tags',
                                         check : false)
                if latest_tag.returncode() == 0
                        time_epoch = run_command(
                                git, 'log', '--no-show-signature', '-1', '--format=%at',
                                     latest_tag.stdout().strip(),
                                check : false).stdout()
                endif
        endif
        if time_epoch == ''
                NEWS = files('NEWS')
                time_epoch = run_command(stat, '-c', '%Y', NEWS,
                                         check : true).stdout()
        endif
        time_epoch = time_epoch.strip().to_int()
endif
conf.set('TIME_EPOCH', time_epoch)

conf.set('CLOCK_VALID_RANGE_USEC_MAX', get_option('clock-valid-range-usec-max'))

default_user_shell = get_option('default-user-shell')
conf.set_quoted('DEFAULT_USER_SHELL',      default_user_shell)
conf.set_quoted('DEFAULT_USER_SHELL_NAME', fs.name(default_user_shell))

foreach tuple : [['system-alloc-uid-min', 'SYS_UID_MIN', 1],  # Also see login.defs(5).
                 ['system-uid-max',       'SYS_UID_MAX', 999],
                 ['system-alloc-gid-min', 'SYS_GID_MIN', 1],
                 ['system-gid-max',       'SYS_GID_MAX', 999]]
        v = get_option(tuple[0])
        if v <= 0
                v = run_command(
                        awk,
                        '/^\s*@0@\s+/ { uid=$2 } END { print uid }'.format(tuple[1]),
                        '/etc/login.defs',
                        check : false).stdout().strip()
                if v == ''
                        v = tuple[2]
                else
                        v = v.to_int()
                endif
        endif
        conf.set(tuple[0].underscorify().to_upper(), v)
endforeach
if conf.get('SYSTEM_ALLOC_UID_MIN') >= conf.get('SYSTEM_UID_MAX')
        error('Invalid uid allocation range')
endif
if conf.get('SYSTEM_ALLOC_GID_MIN') >= conf.get('SYSTEM_GID_MAX')
        error('Invalid gid allocation range')
endif

dynamic_uid_min = get_option('dynamic-uid-min')
dynamic_uid_max = get_option('dynamic-uid-max')
conf.set('DYNAMIC_UID_MIN', dynamic_uid_min)
conf.set('DYNAMIC_UID_MAX', dynamic_uid_max)

container_uid_base_min = get_option('container-uid-base-min')
container_uid_base_max = get_option('container-uid-base-max')
conf.set('CONTAINER_UID_BASE_MIN', container_uid_base_min)
conf.set('CONTAINER_UID_BASE_MAX', container_uid_base_max)

nobody_user = get_option('nobody-user')
nobody_group = get_option('nobody-group')

if not meson.is_cross_build()
        getent_result = run_command('getent', 'passwd', '65534', check : false)
        if getent_result.returncode() == 0
                name = getent_result.stdout().split(':')[0]
                if name != nobody_user
                        warning('\n' +
                                'The local user with the UID 65534 does not match the configured user name "@0@" of the nobody user (its name is @1@).\n'.format(nobody_user, name) +
                                'Your build will result in an user table setup that is incompatible with the local system.')
                endif
        endif
        id_result = run_command('id', '-u', nobody_user, check : false)
        if id_result.returncode() == 0
                id = id_result.stdout().strip().to_int()
                if id != 65534
                        warning('\n' +
                                'The local user with the configured user name "@0@" of the nobody user does not have UID 65534 (it has @1@).\n'.format(nobody_user, id) +
                                'Your build will result in an user table setup that is incompatible with the local system.')
                endif
        endif

        getent_result = run_command('getent', 'group', '65534', check : false)
        if getent_result.returncode() == 0
                name = getent_result.stdout().split(':')[0]
                if name != nobody_group
                        warning('\n' +
                                'The local group with the GID 65534 does not match the configured group name "@0@" of the nobody group (its name is @1@).\n'.format(nobody_group, name) +
                                'Your build will result in an group table setup that is incompatible with the local system.')
                endif
        endif
        id_result = run_command('id', '-g', nobody_group, check : false)
        if id_result.returncode() == 0
                id = id_result.stdout().strip().to_int()
                if id != 65534
                        warning('\n' +
                                'The local group with the configured group name "@0@" of the nobody group does not have GID 65534 (it has @1@).\n'.format(nobody_group, id) +
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

static_ugids = []
foreach option : ['adm-gid',
                  'audio-gid',
                  'cdrom-gid',
                  'dialout-gid',
                  'disk-gid',
                  'input-gid',
                  'kmem-gid',
                  'kvm-gid',
                  'lp-gid',
                  'render-gid',
                  'sgx-gid',
                  'tape-gid',
                  'tty-gid',
                  'users-gid',
                  'utmp-gid',
                  'video-gid',
                  'wheel-gid',
                  'systemd-journal-gid',
                  'systemd-network-uid',
                  'systemd-resolve-uid',
                  'systemd-timesync-uid']
        name = option.underscorify().to_upper()
        val = get_option(option)

        # Ensure provided GID argument is numeric, otherwise fall back to default assignment
        conf.set(name, val > 0 ? val : '-')
        if val > 0
                static_ugids += '@0@:@1@'.format(option, val)
        endif
endforeach

conf.set10('ENABLE_ADM_GROUP', get_option('adm-group'))
conf.set10('ENABLE_WHEEL_GROUP', get_option('wheel-group'))

dev_kvm_mode = get_option('dev-kvm-mode')
conf.set_quoted('DEV_KVM_MODE', dev_kvm_mode) # FIXME: convert to 0o… notation
conf.set10('DEV_KVM_UACCESS', dev_kvm_mode != '0666')
group_render_mode = get_option('group-render-mode')
conf.set_quoted('GROUP_RENDER_MODE', group_render_mode)
conf.set10('GROUP_RENDER_UACCESS', group_render_mode != '0666')

kill_user_processes = get_option('default-kill-user-processes')
conf.set10('KILL_USER_PROCESSES', kill_user_processes)

dns_servers = get_option('dns-servers')
conf.set_quoted('DNS_SERVERS', dns_servers)

ntp_servers = get_option('ntp-servers')
conf.set_quoted('NTP_SERVERS', ntp_servers)

default_locale = get_option('default-locale')
conf.set_quoted('SYSTEMD_DEFAULT_LOCALE', default_locale)

nspawn_locale = get_option('nspawn-locale')
conf.set_quoted('SYSTEMD_NSPAWN_LOCALE', nspawn_locale)

localegen_path = get_option('localegen-path')
if localegen_path != ''
        conf.set_quoted('LOCALEGEN_PATH', localegen_path)
endif
conf.set10('HAVE_LOCALEGEN', localegen_path != '')

conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())

service_watchdog = get_option('service-watchdog')
watchdog_value = service_watchdog == '' ? '' : 'WatchdogSec=' + service_watchdog
conf.set_quoted('SERVICE_WATCHDOG', watchdog_value)

conf.set_quoted('SUSHELL', get_option('debug-shell'))
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

default_user_path = get_option('user-path')
if default_user_path != ''
        conf.set_quoted('DEFAULT_USER_PATH', default_user_path)
endif


#####################################################################

threads = dependency('threads')
librt = cc.find_library('rt')
libm = cc.find_library('m')
libdl = cc.find_library('dl')
libcrypt = cc.find_library('crypt')

# On some architectures, libatomic is required. But on some installations,
# it is found, but actual linking fails. So let's try to use it opportunistically.
# If it is installed, but not needed, it will be dropped because of --as-needed.
if cc.links('''int main(int argc, char **argv) { return 0; }''',
            args : '-latomic',
            name : 'libatomic')
        libatomic = declare_dependency(link_args : '-latomic')
else
        libatomic = []
endif

crypt_header = conf.get('HAVE_CRYPT_H') == 1 ? '''#include <crypt.h>''' : '''#include <unistd.h>'''
foreach ident : [
        ['crypt_ra',               crypt_header],
        ['crypt_preferred_method', crypt_header],
        ['crypt_gensalt_ra',       crypt_header]]

        have = cc.has_function(ident[0], prefix : ident[1], args : '-D_GNU_SOURCE',
                               dependencies : libcrypt)
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

libcap = dependency('libcap', required : false)
if not libcap.found()
        # Compat with Ubuntu 14.04 which ships libcap w/o .pc file
        libcap = cc.find_library('cap')
endif

want_bpf_framework = get_option('bpf-framework')
bpf_compiler = get_option('bpf-compiler')
bpf_framework_required = want_bpf_framework == 'true'

libbpf_version_requirement = '>= 0.1.0'
if bpf_compiler == 'gcc'
        libbpf_version_requirement = '>= 1.0.0'
endif
libbpf = dependency('libbpf', required : bpf_framework_required, version : libbpf_version_requirement)
conf.set10('HAVE_LIBBPF', libbpf.found())

bpftool_strip_version_requirement = '>= 5.13.0'
if bpf_compiler == 'gcc'
        bpftool_strip_version_requirement = '>= 7.0.0'
endif

if want_bpf_framework == 'false' or not libbpf.found() or skip_deps
        conf.set10('BPF_FRAMEWORK', false)
else
        clang_found = false
        clang_supports_bpf = false
        bpf_gcc_found = false
        bpftool_strip = false
        deps_found = false

        if bpf_compiler == 'clang'
                # Support 'versioned' clang/llvm-strip binaries, as seen on Debian/Ubuntu
                # (like clang-10/llvm-strip-10)
                if meson.is_cross_build() or cc.get_id() != 'clang' or cc.cmd_array()[0].contains('afl-clang') or cc.cmd_array()[0].contains('hfuzz-clang')
                        r = find_program('clang', required : bpf_framework_required, version : '>= 10.0.0')
                        clang_found = r.found()
                        if clang_found
                                clang = r.path()
                        endif
                        # Assume that the required flags are supported by the found clang.
                        clang_supports_flags = clang_found
                else
                        clang_found = true
                        clang = cc.cmd_array()
                        clang_supports_flags = cc.has_argument('-Wno-compare-distinct-pointer-types')
                endif

                if clang_found
                        # Check if 'clang -target bpf' is supported.
                        clang_supports_bpf = run_command(clang, '-target', 'bpf', '--print-supported-cpus', check : false).returncode() == 0
                endif
        elif bpf_compiler == 'gcc'
                warning('GCC BPF Compiler support is experimental and not recommended.')
                bpf_gcc = find_program('bpf-gcc',
                                       required : true,
                                       version : '>= 12.1.0')
                bpf_gcc_found = bpf_gcc.found()
        endif

        if clang_supports_bpf or bpf_gcc_found
                # Debian installs this in /usr/sbin/ which is not in $PATH.
                # We check for 'bpftool' first, honouring $PATH, and in /usr/sbin/ for Debian.
                # We use 'bpftool gen object' subcommand for bpftool strip, it was added by d80b2fcbe0a023619e0fc73112f2a02c2662f6ab (v5.13).
                bpftool_strip_required = bpf_framework_required and bpf_compiler == 'gcc'
                bpftool = find_program('bpftool',
                                       '/usr/sbin/bpftool',
                                       required : bpftool_strip_required,
                                       version : bpftool_strip_version_requirement)

                if bpftool.found()
                        bpftool_strip = true
                        deps_found = true
                elif bpf_compiler == 'clang'
                        # We require the 'bpftool gen skeleton' subcommand, it was added by 985ead416df39d6fe8e89580cc1db6aa273e0175 (v5.6).
                        bpftool = find_program('bpftool',
                                               '/usr/sbin/bpftool',
                                               required : bpf_framework_required,
                                               version : '>= 5.6.0')
                endif

                # We use `llvm-strip` as a fallback if `bpftool gen object` strip support is not available.
                if not bpftool_strip and bpftool.found() and clang_supports_bpf
                        if not meson.is_cross_build()
                                llvm_strip_bin = run_command(clang, '--print-prog-name', 'llvm-strip',
                                                             check : true).stdout().strip()
                        else
                                llvm_strip_bin = 'llvm-strip'
                        endif
                        llvm_strip = find_program(llvm_strip_bin, required : bpf_framework_required, version : '>= 10.0.0')
                        deps_found = llvm_strip.found()
                endif
        endif

        # Can build BPF program from source code in restricted C
        conf.set10('BPF_FRAMEWORK', deps_found)
endif

libmount = dependency('mount',
                      version : fuzzer_build ? '>= 0' : '>= 2.30')

want_libfdisk = get_option('fdisk')
if want_libfdisk != 'false' and not skip_deps
        libfdisk = dependency('fdisk',
                              version : '>= 2.32',
                              required : want_libfdisk == 'true')
        have = libfdisk.found()
else
        have = false
        libfdisk = []
endif
conf.set10('HAVE_LIBFDISK', have)

want_pwquality = get_option('pwquality')
if want_pwquality != 'false' and not skip_deps
        libpwquality = dependency('pwquality', required : want_pwquality == 'true')
        have = libpwquality.found()
else
        have = false
        libpwquality = []
endif
conf.set10('HAVE_PWQUALITY', have)

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
                                 version : '>= 2.13',
                                 required : want_apparmor == 'true')
        have = libapparmor.found()
else
        have = false
        libapparmor = []
endif
conf.set10('HAVE_APPARMOR', have)

have = get_option('smack') and get_option('smack-run-label') != ''
conf.set10('HAVE_SMACK_RUN_LABEL', have)
if have
        conf.set_quoted('SMACK_RUN_LABEL', get_option('smack-run-label'))
endif

have = get_option('smack') and get_option('smack-default-process-label') != ''
if have
        conf.set_quoted('SMACK_DEFAULT_PROCESS_LABEL', get_option('smack-default-process-label'))
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

        conf.set10('HAVE_BLKID_PROBE_SET_HINT',
                   have and cc.has_function('blkid_probe_set_hint', dependencies : libblkid))
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
want_libcryptsetup_plugins = get_option('libcryptsetup-plugins')

if want_libcryptsetup_plugins == 'true' and want_libcryptsetup == 'false'
        error('libcryptsetup-plugins can not be requested without libcryptsetup')
endif

if want_libcryptsetup != 'false' and not skip_deps
        libcryptsetup = dependency('libcryptsetup',
                                   version : want_libcryptsetup_plugins == 'true' ? '>= 2.4.0' : '>= 2.0.1',
                                   required : want_libcryptsetup == 'true' or want_libcryptsetup_plugins == 'true')
        have = libcryptsetup.found()

        foreach ident : ['crypt_set_metadata_size',
                         'crypt_activate_by_signed_key',
                         'crypt_token_max']
                have_ident = have and cc.has_function(
                        ident,
                        prefix : '#include <libcryptsetup.h>',
                        dependencies : libcryptsetup)
                conf.set10('HAVE_' + ident.to_upper(), have_ident)
        endforeach
else
        have = false
        libcryptsetup = []
endif
conf.set10('HAVE_LIBCRYPTSETUP', have)

if want_libcryptsetup_plugins != 'false' and not skip_deps
        have = (cc.has_function(
                        'crypt_activate_by_token_pin',
                        prefix : '#include <libcryptsetup.h>',
                        dependencies : libcryptsetup) and
                cc.has_function(
                        'crypt_token_external_path',
                        prefix : '#include <libcryptsetup.h>',
                        dependencies : libcryptsetup))
else
        have = false
endif
conf.set10('HAVE_LIBCRYPTSETUP_PLUGINS', have)

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
conf.set10('CURL_NO_OLDIES', conf.get('BUILD_MODE_DEVELOPER') == 1)

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
                                 version : '>= 3',
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

want_p11kit = get_option('p11kit')
if want_p11kit != 'false' and not skip_deps
        libp11kit = dependency('p11-kit-1',
                               version : '>= 0.23.3',
                               required : want_p11kit == 'true')
        have = libp11kit.found()
else
        have = false
        libp11kit = []
endif
conf.set10('HAVE_P11KIT', have)

want_libfido2 = get_option('libfido2')
if want_libfido2 != 'false' and not skip_deps
        if conf.get('HAVE_OPENSSL') == 1
                libfido2 = dependency('libfido2',
                                      required : want_libfido2 == 'true')
                have = libfido2.found()
        elif want_libfido2 == 'true'
                error('libfido2=true requires openssl')
        else
                have = false
                libfido2 = []
        endif
else
        have = false
        libfido2 = []
endif
conf.set10('HAVE_LIBFIDO2', have)

want_tpm2 = get_option('tpm2')
if want_tpm2 != 'false' and not skip_deps
        tpm2 = dependency('tss2-esys tss2-rc tss2-mu',
                          required : want_tpm2 == 'true')
        have = tpm2.found()
else
        have = false
        tpm2 = []
endif
conf.set10('HAVE_TPM2', have)

want_elfutils = get_option('elfutils')
if want_elfutils != 'false' and not skip_deps
        libdw = dependency('libdw',
                           required : want_elfutils == 'true')
        have = libdw.found()

        # New in elfutils 0.177
        conf.set10('HAVE_DWELF_ELF_E_MACHINE_STRING',
                   have and cc.has_function('dwelf_elf_e_machine_string', dependencies : libdw))
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
        have_xz = libxz.found()
else
        have_xz = false
        libxz = []
endif
conf.set10('HAVE_XZ', have_xz)

want_lz4 = get_option('lz4')
if want_lz4 != 'false' and not skip_deps
        liblz4 = dependency('liblz4',
                            version : '>= 1.3.0',
                            required : want_lz4 == 'true')
        have_lz4 = liblz4.found()
else
        have_lz4 = false
        liblz4 = []
endif
conf.set10('HAVE_LZ4', have_lz4)

want_zstd = get_option('zstd')
if want_zstd != 'false' and not skip_deps
        libzstd = dependency('libzstd',
                             required : want_zstd == 'true',
                             version : '>= 1.4.0')
        have_zstd = libzstd.found()
else
        have_zstd = false
        libzstd = []
endif
conf.set10('HAVE_ZSTD', have_zstd)

conf.set10('HAVE_COMPRESSION', have_xz or have_lz4 or have_zstd)

compression = get_option('default-compression')
if compression == 'auto'
        if have_zstd
                compression = 'zstd'
        elif have_lz4
                compression = 'lz4'
        elif have_xz
                compression = 'xz'
        else
                compression = 'none'
        endif
elif compression == 'zstd' and not have_zstd
        error('default-compression=zstd requires zstd')
elif compression == 'lz4' and not have_lz4
        error('default-compression=lz4 requires lz4')
elif compression == 'xz' and not have_xz
        error('default-compression=xz requires xz')
endif
conf.set('DEFAULT_COMPRESSION', 'COMPRESSION_@0@'.format(compression.to_upper()))

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
if want_pcre2 != 'false' and not skip_deps
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

dbusdatadir = datadir / 'dbus-1'
if conf.get('HAVE_DBUS') == 1
        dbusdatadir = libdbus.get_variable(pkgconfig: 'datadir', default_value: datadir) / 'dbus-1'
endif

dbuspolicydir = get_option('dbuspolicydir')
if dbuspolicydir == ''
        dbuspolicydir = dbusdatadir / 'system.d'
endif

dbussessionservicedir = get_option('dbussessionservicedir')
if dbussessionservicedir == ''
        dbussessionservicedir = dbusdatadir / 'services'
        if conf.get('HAVE_DBUS') == 1
                dbussessionservicedir = libdbus.get_variable(pkgconfig: 'session_bus_services_dir', default_value: dbussessionservicedir)
        endif
endif

dbussystemservicedir = get_option('dbussystemservicedir')
if dbussystemservicedir == ''
        dbussystemservicedir = dbusdatadir / 'system-services'
        if conf.get('HAVE_DBUS') == 1
                dbussystemservicedir = libdbus.get_variable(pkgconfig: 'system_bus_services_dir', default_value: dbussystemservicedir)
        endif
endif

dbus_interfaces_dir = get_option('dbus-interfaces-dir')
if dbus_interfaces_dir == '' or dbus_interfaces_dir == 'yes'
        if meson.is_cross_build() and dbus_interfaces_dir != 'yes'
                dbus_interfaces_dir = 'no'
                warning('Exporting D-Bus interface XML files is disabled during cross build. Pass path or "yes" to force enable.')
        else
                dbus_interfaces_dir = dbusdatadir / 'interfaces'
                if conf.get('HAVE_DBUS') == 1
                        dbus_interfaces_dir = libdbus.get_variable(pkgconfig: 'interfaces_dir', default_value: dbus_interfaces_dir)
                endif
        endif
endif

# We support one or the other. If gcrypt is available, we assume it's there to
# be used, and use it in preference.
opt = get_option('cryptolib')
if opt == 'openssl' and conf.get('HAVE_OPENSSL') == 0
        error('openssl requested as the default cryptolib, but not available')
endif
conf.set10('PREFER_OPENSSL',
           opt == 'openssl' or (opt == 'auto' and conf.get('HAVE_OPENSSL') == 1 and conf.get('HAVE_GCRYPT') == 0))
conf.set10('HAVE_OPENSSL_OR_GCRYPT',
           conf.get('HAVE_OPENSSL') == 1 or conf.get('HAVE_GCRYPT') == 1)
lib_openssl_or_gcrypt = conf.get('PREFER_OPENSSL') == 1 ? [libopenssl] : [libgcrypt, libgpg_error]

dns_over_tls = get_option('dns-over-tls')
if dns_over_tls != 'false'
        if dns_over_tls == 'gnutls' and conf.get('PREFER_OPENSSL') == 1
                error('Sorry, -Ddns-over-tls=gnutls is not supported when openssl is used as the cryptolib')
        endif

        if dns_over_tls == 'gnutls'
                have_openssl = false
        else
                have_openssl = conf.get('HAVE_OPENSSL') == 1
                if dns_over_tls == 'openssl' and not have_openssl
                        error('DNS-over-TLS support was requested with openssl, but dependencies are not available')
                endif
        endif
        if dns_over_tls == 'openssl' or have_openssl
                have_gnutls = false
        else
                have_gnutls = conf.get('HAVE_GNUTLS') == 1 and libgnutls.version().version_compare('>= 3.6.0')
                if dns_over_tls != 'auto' and not have_gnutls
                        str = dns_over_tls == 'gnutls' ? ' with gnutls' : ''
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
conf.set_quoted('DEFAULT_DNS_OVER_TLS_MODE_STR', default_dns_over_tls)

default_mdns = get_option('default-mdns')
conf.set('DEFAULT_MDNS_MODE',
         'RESOLVE_SUPPORT_' + default_mdns.to_upper())
conf.set_quoted('DEFAULT_MDNS_MODE_STR', default_mdns)

default_llmnr = get_option('default-llmnr')
conf.set('DEFAULT_LLMNR_MODE',
         'RESOLVE_SUPPORT_' + default_llmnr.to_upper())
conf.set_quoted('DEFAULT_LLMNR_MODE_STR', default_llmnr)

want_repart = get_option('repart')
if want_repart != 'false'
        have = conf.get('HAVE_LIBFDISK') == 1
        if want_repart == 'true' and not have
                error('repart support was requested, but dependencies are not available')
        endif
else
        have = false
endif
conf.set10('ENABLE_REPART', have)

default_dnssec = get_option('default-dnssec')
if skip_deps
        default_dnssec = 'no'
endif
if default_dnssec != 'no' and conf.get('HAVE_OPENSSL_OR_GCRYPT') == 0
        message('default-dnssec cannot be set to yes or allow-downgrade openssl and gcrypt are disabled. Setting default-dnssec to no.')
        default_dnssec = 'no'
endif
conf.set('DEFAULT_DNSSEC_MODE',
         'DNSSEC_' + default_dnssec.underscorify().to_upper())
conf.set_quoted('DEFAULT_DNSSEC_MODE_STR', default_dnssec)

want_sysupdate = get_option('sysupdate')
if want_sysupdate != 'false'
        have = (conf.get('HAVE_OPENSSL') == 1 and
                conf.get('HAVE_LIBFDISK') == 1)
        if want_sysupdate == 'true' and not have
                error('sysupdate support was requested, but dependencies are not available')
        endif
else
        have = false
endif
conf.set10('ENABLE_SYSUPDATE', have)

want_importd = get_option('importd')
if want_importd != 'false'
        have = (conf.get('HAVE_LIBCURL') == 1 and
                conf.get('HAVE_OPENSSL_OR_GCRYPT') == 1 and
                conf.get('HAVE_ZLIB') == 1 and
                conf.get('HAVE_XZ') == 1)
        if want_importd == 'true' and not have
                error('importd support was requested, but dependencies are not available')
        endif
else
        have = false
endif
conf.set10('ENABLE_IMPORTD', have)

want_kernel_install = get_option('kernel-install')
conf.set10('ENABLE_KERNEL_INSTALL', want_kernel_install)

want_homed = get_option('homed')
if want_homed != 'false'
        have = (conf.get('HAVE_OPENSSL') == 1 and
                conf.get('HAVE_LIBFDISK') == 1 and
                conf.get('HAVE_LIBCRYPTSETUP') == 1)
        if want_homed == 'true' and not have
                error('homed support was requested, but dependencies are not available')
        endif
else
        have = false
endif
conf.set10('ENABLE_HOMED', have)

have = have and conf.get('HAVE_PAM') == 1
conf.set10('ENABLE_PAM_HOME', have)

have = get_option('oomd')
conf.set10('ENABLE_OOMD', have)

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

foreach term : ['analyze',
                'backlight',
                'binfmt',
                'coredump',
                'efi',
                'environment-d',
                'firstboot',
                'gshadow',
                'hibernate',
                'hostnamed',
                'hwdb',
                'idn',
                'ima',
                'initrd',
                'compat-mutable-uid-boundaries',
                'nscd',
                'ldconfig',
                'localed',
                'logind',
                'machined',
                'networkd',
                'nss-myhostname',
                'nss-systemd',
                'portabled',
                'sysext',
                'pstore',
                'quotacheck',
                'randomseed',
                'resolve',
                'rfkill',
                'smack',
                'sysusers',
                'timedated',
                'timesyncd',
                'tmpfiles',
                'tpm',
                'userdb',
                'utmp',
                'vconsole',
                'xdg-autostart']
        have = get_option(term)
        name = 'ENABLE_' + term.underscorify().to_upper()
        conf.set10(name, have)
endforeach

enable_sysusers = conf.get('ENABLE_SYSUSERS') == 1

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

conf.set10('SYSTEMD_SLOW_TESTS_DEFAULT', slow_tests)

############################################################

tests = []
fuzzers = []
catalogs = []

############################################################

# Include these now as they provide gnu-efi detection.
subdir('src/fundamental')
subdir('src/boot/efi')

############################################################

generate_gperfs = find_program('tools/generate-gperfs.py')
make_autosuspend_rules_py = find_program('tools/make-autosuspend-rules.py')
make_directive_index_py = find_program('tools/make-directive-index.py')
make_man_index_py = find_program('tools/make-man-index.py')
meson_render_jinja2 = find_program('tools/meson-render-jinja2.py')
update_dbus_docs_py = find_program('tools/update-dbus-docs.py')
update_man_rules_py = find_program('tools/update-man-rules.py')
update_hwdb_sh = find_program('tools/update-hwdb.sh')
update_hwdb_autosuspend_sh = find_program('tools/update-hwdb-autosuspend.sh')
update_syscall_tables_sh = find_program('tools/update-syscall-tables.sh')
xml_helper_py = find_program('tools/xml_helper.py')
export_dbus_interfaces_py = find_program('tools/dbus_exporter.py')

############################################################

if get_option('b_coverage')
        add_project_arguments('-include', 'src/basic/coverage.h', language : 'c')
endif

############################################################

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

add_project_arguments('-include', 'config.h', language : 'c')

jinja2_cmdline = [meson_render_jinja2, config_h, version_h]

############################################################

# binaries that have --help and are intended for use by humans,
# usually, but not always, installed in /bin.
public_programs = []

# D-Bus introspection XML export
dbus_programs = []

basic_includes = include_directories(
        'src/basic',
        'src/fundamental',
        'src/systemd',
        '.')

libsystemd_includes = [basic_includes, include_directories(
        'src/libsystemd/sd-bus',
        'src/libsystemd/sd-device',
        'src/libsystemd/sd-event',
        'src/libsystemd/sd-hwdb',
        'src/libsystemd/sd-id128',
        'src/libsystemd/sd-journal',
        'src/libsystemd/sd-netlink',
        'src/libsystemd/sd-network',
        'src/libsystemd/sd-resolve')]

includes = [libsystemd_includes, include_directories('src/shared')]

subdir('po')
subdir('catalog')
subdir('src/basic')
subdir('src/libsystemd')
subdir('src/shared')
subdir('src/udev')
subdir('src/libudev')
subdir('src/cryptsetup/cryptsetup-tokens')

alias_target('devel', libsystemd_pc, libudev_pc)

libsystemd = shared_library(
        'systemd',
        version : libsystemd_version,
        include_directories : libsystemd_includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libsystemd_sym_path],
        link_with : [libbasic,
                     libbasic_gcrypt,
                     libbasic_compress],
        link_whole : [libsystemd_static],
        dependencies : [threads,
                        librt],
        link_depends : libsystemd_sym,
        install : true,
        install_tag: 'libsystemd',
        install_dir : rootlibdir)

alias_target('libsystemd', libsystemd)

install_libsystemd_static = static_library(
        'systemd',
        libsystemd_sources,
        basic_sources,
        basic_gcrypt_sources,
        basic_compress_sources,
        fundamental_sources,
        include_directories : libsystemd_includes,
        build_by_default : static_libsystemd != 'false',
        install : static_libsystemd != 'false',
        install_tag: 'libsystemd',
        install_dir : rootlibdir,
        pic : static_libsystemd_pic,
        dependencies : [threads,
                        librt,
                        libxz,
                        libzstd,
                        liblz4,
                        libdl,
                        libcap,
                        libblkid,
                        libmount,
                        libgcrypt,
                        libopenssl],
        c_args : libsystemd_c_args + (static_libsystemd_pic ? [] : ['-fno-PIC']))

libudev = shared_library(
        'udev',
        version : libudev_version,
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libudev_sym_path],
        link_with : [libsystemd_static, libshared_static],
        link_whole : libudev_basic,
        dependencies : [threads],
        link_depends : libudev_sym,
        install : true,
        install_tag: 'libudev',
        install_dir : rootlibdir)

alias_target('libudev', libudev)

install_libudev_static = static_library(
        'udev',
        basic_sources,
        fundamental_sources,
        shared_sources,
        libsystemd_sources,
        libudev_sources,
        include_directories : includes,
        build_by_default : static_libudev != 'false',
        install : static_libudev != 'false',
        install_tag: 'libudev',
        install_dir : rootlibdir,
        link_depends : libudev_sym,
        dependencies : libshared_deps + [libmount],
        c_args : static_libudev_pic ? [] : ['-fno-PIC'],
        pic : static_libudev_pic)

if conf.get('HAVE_LIBCRYPTSETUP_PLUGINS') == 1
        if conf.get('HAVE_TPM2') == 1
                cryptsetup_token_systemd_tpm2 = shared_library(
                        'cryptsetup-token-systemd-tpm2',
                        cryptsetup_token_systemd_tpm2_sources,
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + cryptsetup_token_sym_path],
                        link_with : [lib_cryptsetup_token_common,
                                     libshared],
                        dependencies : [libcryptsetup,
                                        tpm2,
                                        versiondep],
                        link_depends : cryptsetup_token_sym,
                        install_rpath : rootpkglibdir,
                        install : true,
                        install_dir : libcryptsetup_plugins_dir)
        endif

        if conf.get('HAVE_LIBFIDO2') == 1
                cryptsetup_token_systemd_fido2 = shared_library(
                        'cryptsetup-token-systemd-fido2',
                        cryptsetup_token_systemd_fido2_sources,
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + cryptsetup_token_sym_path],
                        link_with : [lib_cryptsetup_token_common,
                                     libshared],
                        dependencies : [libcryptsetup,
                                        libfido2,
                                        versiondep],
                        link_depends : cryptsetup_token_sym,
                        install_rpath : rootpkglibdir,
                        install : true,
                        install_dir : libcryptsetup_plugins_dir)
        endif

        if conf.get('HAVE_P11KIT') == 1
                cryptsetup_token_systemd_pkcs11 = shared_library(
                        'cryptsetup-token-systemd-pkcs11',
                        cryptsetup_token_systemd_pkcs11_sources,
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + cryptsetup_token_sym_path],
                        link_with : [lib_cryptsetup_token_common,
                                     libshared],
                        dependencies : [libcryptsetup,
                                        libp11kit,
                                        versiondep],
                        link_depends : cryptsetup_token_sym,
                        install_rpath : rootpkglibdir,
                        install : true,
                        install_dir : libcryptsetup_plugins_dir)
        endif
endif

############################################################

# systemd-analyze requires 'libcore'
subdir('src/core')
# systemd-journal-remote requires 'libjournal_core'
subdir('src/journal')
# systemd-networkd requires 'libsystemd_network'
subdir('src/libsystemd-network')

subdir('src/analyze')
subdir('src/busctl')
subdir('src/coredump')
subdir('src/cryptenroll')
subdir('src/cryptsetup')
subdir('src/home')
subdir('src/hostname')
subdir('src/import')
subdir('src/journal-remote')
subdir('src/kernel-install')
subdir('src/locale')
subdir('src/login')
subdir('src/machine')
subdir('src/network')
subdir('src/nspawn')
subdir('src/oom')
subdir('src/partition')
subdir('src/portable')
subdir('src/pstore')
subdir('src/resolve')
subdir('src/rpm')
subdir('src/shutdown')
subdir('src/sysext')
subdir('src/systemctl')
subdir('src/sysupdate')
subdir('src/timedate')
subdir('src/timesync')
subdir('src/tmpfiles')
subdir('src/userdb')
subdir('src/xdg-autostart-generator')

subdir('src/systemd')

subdir('src/test')
subdir('src/fuzz')
subdir('rules.d')
subdir('test')

############################################################

# only static linking apart from libdl, to make sure that the
# module is linked to all libraries that it uses.
test_dlopen = executable(
        'test-dlopen',
        test_dlopen_c,
        include_directories : includes,
        link_with : [libbasic],
        dependencies : [libdl],
        build_by_default : want_tests != 'false')

foreach tuple : [['myhostname', 'ENABLE_NSS_MYHOSTNAME'],
                 ['systemd',    'ENABLE_NSS_SYSTEMD', ['nss-systemd.h', 'userdb-glue.c', 'userdb-glue.h']],
                 ['mymachines', 'ENABLE_NSS_MYMACHINES'],
                 ['resolve',    'ENABLE_NSS_RESOLVE', [], resolve_includes]]

        condition = tuple[1] == '' or conf.get(tuple[1]) == 1
        if condition
                module = tuple[0]

                sym = 'src/nss-@0@/nss-@0@.sym'.format(module)
                version_script_arg = project_source_root / sym

                sources = ['src/nss-@0@/nss-@0@.c'.format(module)]
                if tuple.length() > 2
                        foreach s : tuple[2]
                                sources += ['src/nss-@0@/@1@'.format(module, s)]
                        endforeach
                endif

                incs = tuple.length() > 3 ? tuple[3] : includes

                nss = shared_library(
                        'nss_' + module,
                        sources,
                        version : '2',
                        include_directories : incs,
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
                        install_tag : 'nss',
                        install_dir : rootlibdir)

                # We cannot use shared_module because it does not support version suffix.
                # Unfortunately shared_library insists on creating the symlink…
                meson.add_install_script('sh', '-c',
                                         'rm $DESTDIR@0@/libnss_@1@.so'
                                         .format(rootlibdir, module),
                                         install_tag : 'nss'
                                         )

                if want_tests != 'false'
                        test('dlopen-nss_' + module,
                             test_dlopen,
                             # path to dlopen must include a slash
                             args : nss.full_path(),
                             depends : nss)
                endif
        endif
endforeach

############################################################

exe = executable(
        'systemd',
        systemd_sources,
        include_directories : includes,
        link_with : [libcore,
                     libshared],
        dependencies : [versiondep,
                        libseccomp],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)
dbus_programs += exe
public_programs += exe

meson.add_install_script(meson_make_symlink,
                         rootlibexecdir / 'systemd',
                         rootsbindir / 'init')

exe = executable(
        'systemd-analyze',
        systemd_analyze_sources,
        include_directories : core_includes,
        link_with : [libcore,
                     libshared],
        dependencies : [versiondep,
                        libseccomp],
        install_rpath : rootpkglibdir,
        install : conf.get('ENABLE_ANALYZE') == 1)
public_programs += exe

if want_tests != 'false'
        test('test-compare-versions',
             test_compare_versions_sh,
             args : exe.full_path())
endif

executable(
        'systemd-journald',
        systemd_journald_sources,
        include_directories : includes,
        link_with : [libjournal_core,
                     libshared],
        dependencies : [threads,
                        libxz,
                        liblz4,
                        libselinux,
                        libzstd],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

public_programs += executable(
        'systemd-cat',
        systemd_cat_sources,
        include_directories : includes,
        link_with : [libjournal_core,
                     libshared],
        dependencies : [threads],
        install_rpath : rootpkglibdir,
        install : true)

if get_option('link-journalctl-shared')
        journalctl_link_with = [libshared]
else
        journalctl_link_with = [libsystemd_static,
                                libshared_static,
                                libbasic_gcrypt]
endif

public_programs += executable(
        'journalctl',
        journalctl_sources,
        include_directories : includes,
        link_with : [journalctl_link_with],
        dependencies : [threads,
                        libdl,
                        libxz,
                        liblz4,
                        libzstd,
                        libdl],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

executable(
        'systemd-getty-generator',
        'src/getty-generator/getty-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

executable(
        'systemd-debug-generator',
        'src/debug-generator/debug-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

executable(
        'systemd-run-generator',
        'src/run-generator/run-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

exe = executable(
        'systemd-fstab-generator',
        'src/fstab-generator/fstab-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

meson.add_install_script(meson_make_symlink,
                         systemgeneratordir / 'systemd-fstab-generator',
                         rootlibexecdir / 'systemd-sysroot-fstab-check')

if want_tests != 'false'
        test('test-fstab-generator',
             test_fstab_generator_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : exe.full_path(),
             depends : exe)
endif

if conf.get('ENABLE_ENVIRONMENT_D') == 1
        executable(
                '30-systemd-environment-d-generator',
                'src/environment-d-generator/environment-d-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : userenvgeneratordir)

        meson.add_install_script(meson_make_symlink,
                                 sysconfdir / 'environment',
                                 environmentdir / '99-environment.conf')
endif

if conf.get('ENABLE_HIBERNATE') == 1
        executable(
                'systemd-hibernate-resume-generator',
                'src/hibernate-resume/hibernate-resume-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        executable(
                'systemd-hibernate-resume',
                'src/hibernate-resume/hibernate-resume.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('HAVE_BLKID') == 1
        executable(
                'systemd-gpt-auto-generator',
                'src/gpt-auto-generator/gpt-auto-generator.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : libblkid,
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        public_programs += executable(
                'systemd-dissect',
                'src/dissect/dissect.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_RESOLVE') == 1
        dbus_programs += executable(
                'systemd-resolved',
                systemd_resolved_sources,
                include_directories : resolve_includes,
                link_with : [libshared,
                             libbasic_gcrypt,
                             libsystemd_resolve_core],
                dependencies : systemd_resolved_dependencies,
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'resolvectl',
                resolvectl_sources,
                include_directories : includes,
                link_with : [libshared,
                             libbasic_gcrypt,
                             libsystemd_resolve_core],
                dependencies : [threads,
                                lib_openssl_or_gcrypt,
                                libm,
                                libidn],
                install_rpath : rootpkglibdir,
                install : true)

        meson.add_install_script(meson_make_symlink,
                                 bindir / 'resolvectl',
                                 rootsbindir / 'resolvconf')

        meson.add_install_script(meson_make_symlink,
                                 bindir / 'resolvectl',
                                 bindir / 'systemd-resolve')
endif

if conf.get('ENABLE_LOGIND') == 1
        dbus_programs += executable(
                'systemd-logind',
                systemd_logind_sources,
                include_directories : includes,
                link_with : [liblogind_core,
                             libshared],
                dependencies : [threads,
                                libacl],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'loginctl',
                loginctl_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                liblz4,
                                libxz,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)

        public_programs += executable(
                'systemd-inhibit',
                'src/login/inhibit.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)

        if conf.get('HAVE_PAM') == 1
                version_script_arg = project_source_root / pam_systemd_sym
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
                        install_tag : 'pam',
                        install_dir : pamlibdir)

                if want_tests != 'false'
                        test('dlopen-pam_systemd',
                             test_dlopen,
                             # path to dlopen must include a slash
                             args : pam_systemd.full_path(),
                             depends : pam_systemd)
                endif
        endif

        executable(
                'systemd-user-runtime-dir',
                user_runtime_dir_sources,
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('HAVE_PAM') == 1
        executable(
                'systemd-user-sessions',
                'src/user-sessions/user-sessions.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('HAVE_BLKID') == 1 and conf.get('HAVE_GNU_EFI') == 1
        if get_option('link-boot-shared')
                boot_link_with = [libshared]
        else
                boot_link_with = [libsystemd_static, libshared_static]
        endif

        public_programs += executable(
                'bootctl',
                'src/boot/bootctl.c',
                include_directories : includes,
                link_with : [boot_link_with],
                dependencies : [libblkid],
                install_rpath : rootpkglibdir,
                install : true)

        public_programs += executable(
                'systemd-bless-boot',
                'src/boot/bless-boot.c',
                include_directories : includes,
                link_with : [boot_link_with],
                dependencies : [libblkid],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-bless-boot-generator',
                'src/boot/bless-boot-generator.c',
                include_directories : includes,
                link_with : [boot_link_with],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        if conf.get('HAVE_OPENSSL') == 1 and conf.get('HAVE_TPM2') == 1
                executable(
                        'systemd-measure',
                        'src/boot/measure.c',
                        include_directories : includes,
                        link_with : [libshared],
                        dependencies : [libopenssl],
                        install_rpath : rootpkglibdir,
                        install : true,
                        install_dir : rootlibexecdir)
                executable(
                        'systemd-pcrphase',
                        'src/boot/pcrphase.c',
                        include_directories : includes,
                        link_with : [libshared],
                        dependencies : [libopenssl, tpm2],
                        install_rpath : rootpkglibdir,
                        install : true,
                        install_dir : rootlibexecdir)
        endif
endif

executable(
        'systemd-boot-check-no-failures',
        'src/boot/boot-check-no-failures.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [libblkid],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

public_programs += executable(
        'systemd-socket-activate',
        'src/activate/activate.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [threads],
        install_rpath : rootpkglibdir,
        install : true)

systemctl = executable(
        'systemctl',
        systemctl_sources,
        include_directories : includes,
        link_with : systemctl_link_with,
        dependencies : [threads,
                        libcap,
                        libselinux,
                        libxz,
                        liblz4,
                        libzstd],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)
public_programs += systemctl

if conf.get('ENABLE_PORTABLED') == 1
        dbus_programs += executable(
                'systemd-portabled',
                systemd_portabled_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads, libselinux],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'portablectl',
                'src/portable/portablectl.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
endif

if conf.get('ENABLE_SYSEXT') == 1
        public_programs += executable(
                'systemd-sysext',
                systemd_sysext_sources,
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
endif

if conf.get('ENABLE_USERDB') == 1
        executable(
                'systemd-userwork',
                systemd_userwork_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-userdbd',
                systemd_userdbd_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'userdbctl',
                userdbctl_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_HOMED') == 1
        executable(
                'systemd-homework',
                systemd_homework_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libblkid,
                                libcrypt,
                                libopenssl,
                                libfdisk,
                                libp11kit],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        dbus_programs += executable(
                'systemd-homed',
                systemd_homed_sources,
                include_directories : home_includes,
                link_with : [libshared],
                dependencies : [threads,
                                libcrypt,
                                libopenssl,
                                libm],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'homectl',
                homectl_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libcrypt,
                                libopenssl,
                                libp11kit,
                                libdl],
                install_rpath : rootpkglibdir,
                install : true)

        if conf.get('HAVE_PAM') == 1
                version_script_arg = project_source_root / pam_systemd_home_sym
                pam_systemd_home = shared_library(
                        'pam_systemd_home',
                        pam_systemd_home_c,
                        name_prefix : '',
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + version_script_arg],
                        link_with : [libsystemd_static,
                                     libshared_static],
                        dependencies : [threads,
                                        libpam,
                                        libpam_misc,
                                        libcrypt],
                        link_depends : pam_systemd_home_sym,
                        install : true,
                        install_tag : 'pam',
                        install_dir : pamlibdir)

                if want_tests != 'false'
                        test('dlopen-pam_systemd_home',
                             test_dlopen,
                             # path to dlopen must include a slash
                             args : pam_systemd_home.full_path(),
                             depends : pam_systemd_home)
                endif
        endif
endif

foreach alias : (['halt', 'poweroff', 'reboot', 'shutdown'] +
                 (conf.get('HAVE_SYSV_COMPAT') == 1 ? ['runlevel', 'telinit'] : []))
        meson.add_install_script(meson_make_symlink,
                                 rootbindir / 'systemctl',
                                 rootsbindir / alias)
endforeach

meson.add_install_script(meson_make_symlink,
                         rootbindir / 'udevadm',
                         rootlibexecdir / 'systemd-udevd')

if conf.get('ENABLE_BACKLIGHT') == 1
        executable(
                'systemd-backlight',
                'src/backlight/backlight.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RFKILL') == 1
        executable(
                'systemd-rfkill',
                'src/rfkill/rfkill.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

executable(
        'systemd-system-update-generator',
        'src/system-update-generator/system-update-generator.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : systemgeneratordir)

if conf.get('HAVE_LIBCRYPTSETUP') == 1
        executable(
                'systemd-cryptsetup',
                systemd_cryptsetup_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libcryptsetup,
                                libp11kit],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-cryptsetup-generator',
                'src/cryptsetup/cryptsetup-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        executable(
                'systemd-veritysetup',
                'src/veritysetup/veritysetup.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libcryptsetup],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-veritysetup-generator',
                'src/veritysetup/veritysetup-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        public_programs += executable(
                'systemd-cryptenroll',
                systemd_cryptenroll_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libcryptsetup,
                                libdl,
                                libopenssl,
                                libp11kit],
                install_rpath : rootpkglibdir,
                install : true)

        executable(
                'systemd-integritysetup',
                ['src/integritysetup/integritysetup.c', 'src/integritysetup/integrity-util.c'],
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libcryptsetup],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-integritysetup-generator',
                ['src/integritysetup/integritysetup-generator.c', 'src/integritysetup/integrity-util.c'],
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)
endif

if conf.get('HAVE_SYSV_COMPAT') == 1
        exe = executable(
                'systemd-sysv-generator',
                'src/sysv-generator/sysv-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)

        sysv_generator_test_py = find_program('test/sysv-generator-test.py')
        if want_tests != 'false'
                test('sysv-generator-test',
                     sysv_generator_test_py,
                     depends : exe)
        endif

        executable(
                'systemd-rc-local-generator',
                'src/rc-local-generator/rc-local-generator.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : systemgeneratordir)
endif

if conf.get('ENABLE_XDG_AUTOSTART') == 1
        executable(
                'systemd-xdg-autostart-generator',
                systemd_xdg_autostart_generator_sources,
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : usergeneratordir)

        executable(
                'systemd-xdg-autostart-condition',
                'src/xdg-autostart-generator/xdg-autostart-condition.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_HOSTNAMED') == 1
        dbus_programs += executable(
                'systemd-hostnamed',
                'src/hostname/hostnamed.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'hostnamectl',
                'src/hostname/hostnamectl.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_LOCALED') == 1
        if conf.get('HAVE_XKBCOMMON') == 1
                # logind will load libxkbcommon.so dynamically on its own, but we still
                # need to specify where the headers are
                deps = [libdl, libxkbcommon.partial_dependency(compile_args: true)]
        else
                deps = []
        endif

        dbus_programs += executable(
                'systemd-localed',
                systemd_localed_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : deps,
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'localectl',
                localectl_sources,
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_TIMEDATED') == 1
        dbus_programs += executable(
                'systemd-timedated',
                'src/timedate/timedated.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_TIMEDATECTL') == 1
        public_programs += executable(
                'timedatectl',
                'src/timedate/timedatectl.c',
                include_directories : includes,
                install_rpath : rootpkglibdir,
                link_with : [libshared],
                dependencies : [libm],
                install : true)
endif

if conf.get('ENABLE_TIMESYNCD') == 1
        executable(
                'systemd-timesyncd',
                systemd_timesyncd_sources,
                include_directories : includes,
                link_with : [libtimesyncd_core],
                dependencies : [threads,
                                libm],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        executable(
                'systemd-time-wait-sync',
                'src/timesync/wait-sync.c',
                include_directories : includes,
                link_with : [libtimesyncd_core],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_MACHINED') == 1
        dbus_programs += executable(
                'systemd-machined',
                systemd_machined_sources,
                include_directories : includes,
                link_with : [libmachine_core,
                             libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'machinectl',
                'src/machine/machinectl.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
endif

if conf.get('ENABLE_IMPORTD') == 1
        dbus_programs += executable(
                'systemd-importd',
                systemd_importd_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        systemd_pull = executable(
                'systemd-pull',
                systemd_pull_sources,
                include_directories : includes,
                link_with : [libshared,
                             lib_import_common],
                dependencies : [versiondep,
                                libcurl,
                                lib_openssl_or_gcrypt,
                                libz,
                                libbzip2,
                                libxz],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        systemd_import = executable(
                'systemd-import',
                systemd_import_sources,
                include_directories : includes,
                link_with : [libshared,
                             lib_import_common],
                dependencies : [libcurl,
                                libz,
                                libbzip2,
                                libxz],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        systemd_import_fs = executable(
                'systemd-import-fs',
                systemd_import_fs_sources,
                include_directories : includes,
                link_with : [libshared,
                             lib_import_common],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        systemd_export = executable(
                'systemd-export',
                systemd_export_sources,
                include_directories : includes,
                link_with : [libshared,
                             lib_import_common],
                dependencies : [libcurl,
                                libz,
                                libbzip2,
                                libxz],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += [systemd_pull, systemd_import, systemd_import_fs, systemd_export]
endif

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_LIBCURL') == 1
        public_programs += executable(
                'systemd-journal-upload',
                systemd_journal_upload_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [versiondep,
                                threads,
                                libcurl,
                                libgnutls,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_REMOTE') == 1 and conf.get('HAVE_MICROHTTPD') == 1
        public_programs += executable(
                'systemd-journal-remote',
                systemd_journal_remote_sources,
                include_directories : journal_includes,
                link_with : [libshared,
                             libsystemd_journal_remote],
                dependencies : [threads,
                                libmicrohttpd,
                                libgnutls,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'systemd-journal-gatewayd',
                systemd_journal_gatewayd_sources,
                include_directories : journal_includes,
                link_with : [libshared],
                dependencies : [threads,
                                libmicrohttpd,
                                libgnutls,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_COREDUMP') == 1
        executable(
                'systemd-coredump',
                systemd_coredump_sources,
                include_directories : includes,
                link_with : [libshared,
                             libbasic_compress],
                dependencies : [threads,
                                libacl,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'coredumpctl',
                coredumpctl_sources,
                include_directories : includes,
                link_with : [libshared,
                             libbasic_compress],
                dependencies : [threads,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_PSTORE') == 1
        executable(
                'systemd-pstore',
                systemd_pstore_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libacl,
                                libxz,
                                liblz4,
                                libzstd],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_OOMD') == 1
        dbus_programs += executable('systemd-oomd',
                   systemd_oomd_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [libatomic],
                   install_rpath : rootpkglibdir,
                   install : true,
                   install_dir : rootlibexecdir)

        public_programs += executable(
                'oomctl',
                oomctl_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [],
                install_rpath : rootpkglibdir,
                install : true)
endif

if conf.get('ENABLE_BINFMT') == 1
        public_programs += executable(
                'systemd-binfmt',
                'src/binfmt/binfmt.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(binfmtdir))
        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'binfmt.d'))
        endif
endif

if conf.get('ENABLE_SYSUPDATE') == 1
        exe = executable(
                'systemd-sysupdate',
                systemd_sysupdate_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libblkid,
                                libfdisk,
                                libopenssl],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
        public_programs += exe
endif

if conf.get('ENABLE_VCONSOLE') == 1
        executable(
                'systemd-vconsole-setup',
                'src/vconsole/vconsole-setup.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RANDOMSEED') == 1
        executable(
                'systemd-random-seed',
                'src/random-seed/random-seed.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_FIRSTBOOT') == 1
        public_programs += executable(
                'systemd-firstboot',
                'src/firstboot/firstboot.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libcrypt],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
endif

executable(
        'systemd-remount-fs',
        'src/remount-fs/remount-fs.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-machine-id-setup',
        'src/machine-id-setup/machine-id-setup-main.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

executable(
        'systemd-fsck',
        'src/fsck/fsck.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable('systemd-growfs',
           'src/partition/growfs.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootpkglibdir,
           install : true,
           install_dir : rootlibexecdir)

executable(
        'systemd-makefs',
        'src/partition/makefs.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-sleep',
        'src/sleep/sleep.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

if install_sysconfdir_samples
        install_data('src/sleep/sleep.conf',
                     install_dir : pkgsysconfdir)
endif

public_programs += executable(
        'systemd-sysctl',
        'src/sysctl/sysctl.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-ac-power',
        'src/ac-power/ac-power.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

public_programs += executable(
        'systemd-detect-virt',
        'src/detect-virt/detect-virt.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'systemd-delta',
        'src/delta/delta.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'systemd-escape',
        'src/escape/escape.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

public_programs += executable(
        'systemd-notify',
        'src/notify/notify.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

public_programs += executable(
        'systemd-creds',
        'src/creds/creds.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [threads,
                        libopenssl],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

executable(
        'systemd-volatile-root',
        'src/volatile-root/volatile-root.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : conf.get('ENABLE_INITRD') == 1,
        install_dir : rootlibexecdir)

executable(
        'systemd-cgroups-agent',
        'src/cgroups-agent/cgroups-agent.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

systemd_id128 = executable(
        'systemd-id128',
        'src/id128/id128.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)
public_programs += systemd_id128

if want_tests != 'false'
        test('test-systemctl-enable',
             test_systemctl_enable_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : [systemctl.full_path(),
                     systemd_id128.full_path()])
endif

public_programs += executable(
        'systemd-path',
        'src/path/path.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'systemd-ask-password',
        'src/ask-password/ask-password.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

executable(
        'systemd-reply-password',
        'src/reply-password/reply-password.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

public_programs += executable(
        'systemd-tty-ask-password-agent',
        'src/tty-ask-password-agent/tty-ask-password-agent.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootbindir)

public_programs += executable(
        'systemd-cgls',
        'src/cgls/cgls.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'systemd-cgtop',
        'src/cgtop/cgtop.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

executable(
        'systemd-initctl',
        'src/initctl/initctl.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : (conf.get('HAVE_SYSV_COMPAT') == 1),
        install_dir : rootlibexecdir)

public_programs += executable(
        'systemd-mount',
        'src/mount/mount-tool.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies: [libmount],
        install_rpath : rootpkglibdir,
        install : true)

meson.add_install_script(meson_make_symlink,
                         'systemd-mount', bindir / 'systemd-umount')

public_programs += executable(
        'systemd-run',
        'src/run/run.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'systemd-stdio-bridge',
        'src/stdio-bridge/stdio-bridge.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [versiondep],
        install_rpath : rootpkglibdir,
        install : true)

public_programs += executable(
        'busctl',
        busctl_sources,
        include_directories : includes,
        link_with : [libshared],
        dependencies : [versiondep],
        install_rpath : rootpkglibdir,
        install : true)

if enable_sysusers
        exe = executable(
                'systemd-sysusers',
                'src/sysusers/sysusers.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
        public_programs += exe

        if want_tests != 'false'
                test('test-sysusers',
                     test_sysusers_sh,
                     # https://github.com/mesonbuild/meson/issues/2681
                     args : exe.full_path())
        endif

        if have_standalone_binaries
                exe = executable(
                        'systemd-sysusers.standalone',
                        'src/sysusers/sysusers.c',
                        include_directories : includes,
                        c_args : '-DSTANDALONE',
                        link_with : [libshared_static,
                                     libbasic,
                                     libbasic_gcrypt,
                                     libsystemd_static],
                        install : true,
                        install_dir : rootbindir)
                public_programs += exe

                if want_tests != 'false'
                        test('test-sysusers.standalone',
                             test_sysusers_sh,
                             # https://github.com/mesonbuild/meson/issues/2681
                             args : exe.full_path())
                endif
        endif
endif

if conf.get('ENABLE_TMPFILES') == 1
        exe = executable(
                'systemd-tmpfiles',
                systemd_tmpfiles_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libacl],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
        public_programs += exe

        if want_tests != 'false'
                test('test-systemd-tmpfiles',
                     test_systemd_tmpfiles_py,
                     # https://github.com/mesonbuild/meson/issues/2681
                     args : exe.full_path())
        endif

        if have_standalone_binaries
                exe = executable(
                        'systemd-tmpfiles.standalone',
                        systemd_tmpfiles_sources,
                        include_directories : includes,
                        c_args : '-DSTANDALONE',
                        link_with : [libshared_static,
                                     libbasic,
                                     libbasic_gcrypt,
                                     libsystemd_static],
                        dependencies : [libacl],
                        install : true,
                        install_dir : rootbindir)
                public_programs += exe

                if want_tests != 'false'
                        test('test-systemd-tmpfiles.standalone',
                             test_systemd_tmpfiles_py,
                             # https://github.com/mesonbuild/meson/issues/2681
                             args : exe.full_path())
                endif
        endif
endif

if conf.get('ENABLE_HWDB') == 1
        systemd_hwdb = executable(
                'systemd-hwdb',
                'src/hwdb/hwdb.c',
                include_directories : includes,
                link_with : udev_link_with,
                install_rpath : udev_rpath,
                install : true,
                install_dir : rootbindir)
        public_programs += systemd_hwdb

        if want_tests != 'false'
                test('hwdb-test',
                     hwdb_test_sh,
                     suite : 'dist-check',
                     args : [systemd_hwdb.full_path()],
                     timeout : 90)
        endif
endif

if conf.get('ENABLE_QUOTACHECK') == 1
        executable(
                'systemd-quotacheck',
                'src/quotacheck/quotacheck.c',
                include_directories : includes,
                link_with : [libshared],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)
endif

public_programs += executable(
        'systemd-socket-proxyd',
        'src/socket-proxy/socket-proxyd.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [threads],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

udevadm = executable(
        'udevadm',
        udevadm_sources,
        include_directories : includes,
        link_with : [libudevd_core],
        dependencies : [versiondep,
                        threads,
                        libkmod,
                        libidn,
                        libacl,
                        libblkid],
        install_rpath : udev_rpath,
        install : true,
        install_dir : rootbindir)
public_programs += udevadm

if conf.get('ENABLE_REPART') == 1
        exe = executable(
                'systemd-repart',
                systemd_repart_sources,
                include_directories : includes,
                link_with : [libshared],
                dependencies : [threads,
                                libblkid,
                                libfdisk,
                                libopenssl],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
        public_programs += exe
endif

executable(
        'systemd-shutdown',
        systemd_shutdown_sources,
        include_directories : includes,
        link_with : [libshared],
        dependencies : [libmount],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-update-done',
        'src/update-done/update-done.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

executable(
        'systemd-update-utmp',
        'src/update-utmp/update-utmp.c',
        include_directories : includes,
        link_with : [libshared],
        dependencies : [libaudit],
        install_rpath : rootpkglibdir,
        install : (conf.get('ENABLE_UTMP') == 1),
        install_dir : rootlibexecdir)

if conf.get('HAVE_KMOD') == 1
        executable(
                'systemd-modules-load',
                'src/modules-load/modules-load.c',
                include_directories : includes,
                link_with : [libshared],
                dependencies : [libkmod],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(modulesloaddir))
        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(sysconfdir / 'modules-load.d'))
        endif
endif

public_programs += executable(
        'systemd-nspawn',
        systemd_nspawn_sources,
        include_directories : includes,
        link_with : [libnspawn_core,
                     libshared],
        dependencies : [libblkid,
                        libseccomp],
        install_rpath : rootpkglibdir,
        install : true)

if conf.get('ENABLE_NETWORKD') == 1
        dbus_programs += executable(
                'systemd-networkd',
                systemd_networkd_sources,
                include_directories : network_includes,
                link_with : [libnetworkd_core,
                             libsystemd_network,
                             networkd_link_with],
                dependencies : [threads],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'systemd-networkd-wait-online',
                systemd_networkd_wait_online_sources,
                include_directories : includes,
                link_with : [networkd_link_with],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootlibexecdir)

        public_programs += executable(
                'networkctl',
                networkctl_sources,
                include_directories : libsystemd_network_includes,
                link_with : [libsystemd_network,
                             networkd_link_with],
                install_rpath : rootpkglibdir,
                install : true,
                install_dir : rootbindir)
endif

exe = executable(
        'systemd-network-generator',
        network_generator_sources,
        include_directories : includes,
        link_with : [networkd_link_with],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

if want_tests != 'false'
        test('test-network-generator-conversion',
             test_network_generator_conversion_sh,
             # https://github.com/mesonbuild/meson/issues/2681
             args : exe.full_path(),
             depends : exe)
endif

executable(
        'systemd-sulogin-shell',
        'src/sulogin-shell/sulogin-shell.c',
        include_directories : includes,
        link_with : [libshared],
        install_rpath : rootpkglibdir,
        install : true,
        install_dir : rootlibexecdir)

exe = custom_target(
        'kernel-install',
        input : kernel_install_in,
        output : 'kernel-install',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_kernel_install,
        install_mode : 'rwxr-xr-x',
        install_dir : bindir)
public_programs += exe

if want_tests != 'false'
        test('test-kernel-install',
             test_kernel_install_sh,
             args : [exe.full_path(), loaderentry_install])
endif

############################################################

runtest_env = custom_target(
        'systemd-runtest.env',
        output : 'systemd-runtest.env',
        command : [sh, '-c',
                   '{ echo SYSTEMD_TEST_DATA=@0@; echo SYSTEMD_CATALOG_DIR=@1@; } >@OUTPUT@'.format(
                           project_source_root / 'test',
                           project_build_root / 'catalog')],
        depends : catalogs,
        build_by_default : true)

test_cflags = ['-DTEST_CODE=1']
# We intentionally do not do inline initializations with definitions for a
# bunch of _cleanup_ variables in tests, to ensure valgrind is triggered if we
# use the variable unexpectedly. This triggers a lot of maybe-uninitialized
# false positives when the combination of -O2 and -flto is used. Suppress them.
if '-O2' in c_args and '-flto=auto' in c_args
        test_cflags += cc.first_supported_argument('-Wno-maybe-uninitialized')
endif

foreach tuple : tests
        sources = tuple[0]
        link_with = tuple.length() > 1 and tuple[1].length() > 0 ? tuple[1] : [libshared]
        dependencies = tuple.length() > 2 ? tuple[2] : []
        incs = tuple.length() > 3 and tuple[3].length() > 0 ? tuple[3] : includes
        condition = tuple.length() > 4 ? tuple[4] : ''
        type = tuple.length() > 5 ? tuple[5] : ''
        defs = tuple.length() > 6 ? tuple[6] : []
        defs += test_cflags
        parallel = tuple.length() > 7 ? tuple[7] : true
        timeout = 30

        # FIXME: Use fs.stem() with meson >= 0.54.0
        name = '@0@'.format(sources[0]).split('/')[-1].split('.')[0]
        if type.startswith('timeout=')
                timeout = type.split('=')[1].to_int()
                type = ''
        endif

        suite = fs.name(fs.parent('@0@'.format(sources[0])))
        # FIXME: Use str.replace() with meson >= 0.58.0
        suite = suite.split('sd-')[-1]

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
                        install_rpath : rootpkglibdir,
                        install : install_tests,
                        install_dir : testsdir / type,
                        link_depends : runtest_env)

                if type == 'manual'
                        message('@0@ is a manual test'.format(name))
                elif type == 'unsafe' and want_tests != 'unsafe'
                        message('@0@ is an unsafe test'.format(name))
                elif want_tests != 'false'
                        test(name, exe,
                             env : test_env,
                             timeout : timeout,
                             suite : suite,
                             is_parallel : parallel)
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
        include_directories : libudev_includes,
        c_args : ['-Wno-deprecated-declarations'] + test_cflags,
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
        include_directories : libudev_includes,
        c_args : ['-Wno-deprecated-declarations'] + test_cflags,
        link_with : [install_libudev_static],
        build_by_default : want_tests != 'false' and static_libudev_pic,
        install : install_tests and static_libudev_pic,
        install_dir : testsdir)
if want_tests != 'false' and static_libudev_pic
        test('test-libudev-static-sym', exe)
endif

############################################################

fuzzer_exes = []

foreach tuple : fuzzers
        sources = tuple[0]
        link_with = tuple.length() > 1 and tuple[1].length() > 0 ? tuple[1] : [libshared]
        dependencies = tuple.length() > 2 ? tuple[2] : []
        incs = tuple.length() > 3 and tuple[3].length() > 0 ? tuple[3] : includes
        defs = tuple.length() > 4 ? tuple[4] : []
        link_args = []

        if want_ossfuzz
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

        # FIXME: Use fs.stem() with meson >= 0.54.0
        name = '@0@'.format(sources[0]).split('/')[-1].split('.')[0]

        exe = executable(
                name,
                sources,
                include_directories : [incs, include_directories('src/fuzz')],
                link_with : link_with,
                dependencies : dependencies,
                c_args : defs + test_cflags,
                link_args: link_args,
                install : false,
                build_by_default : fuzzer_build)
        fuzzer_exes += exe

        if want_tests != 'false'
                # Run the fuzz regression tests without any sanitizers enabled.
                # Additional invocations with sanitizers may be added below.
                foreach p : fuzz_regression_tests
                        b = p.split('/')[-2]
                        c = p.split('/')[-1]

                        if b == name
                                test('@0@_@1@'.format(b, c),
                                     exe,
                                     suite : 'fuzzers',
                                     args : [project_source_root / p])
                        endif
                endforeach
        endif
endforeach

alias_target('fuzzers', fuzzer_exes)

############################################################

subdir('modprobe.d')
subdir('sysctl.d')
subdir('sysusers.d')
subdir('tmpfiles.d')
subdir('hwdb.d')
subdir('units')
subdir('presets')
subdir('network')
subdir('man')
subdir('shell-completion/bash')
subdir('shell-completion/zsh')
subdir('docs/sysvinit')
subdir('docs/var-log')

install_subdir('factory/etc',
               install_dir : factorydir)
subdir('factory/templates')

if install_sysconfdir
        install_data('xorg/50-systemd-user.sh',
                     install_dir : xinitrcdir)
endif
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
             install_dir : docdir)

install_subdir('LICENSES',
               install_dir : docdir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemdstatedir))
meson.add_install_script('sh', '-c', 'touch $DESTDIR@0@'.format(prefixdir))

############################################################

# Ensure that changes to the docs/ directory do not break the
# basic Github pages build. But only run it in developer mode,
# as it might be fragile due to changes in the tooling, and it is
# not generally useful for users.
jekyll = find_program('jekyll', required : false)
if get_option('mode') == 'developer' and want_tests != 'false' and jekyll.found()
        test('github-pages',
             jekyll,
             suite : 'dist-check',
             args : ['build',
                     '--source', project_source_root / 'docs',
                     '--destination', project_build_root / '_site'])
endif

############################################################

check_help = find_program('tools/check-help.sh')
check_version = find_program('tools/check-version.sh')

foreach exec : public_programs
        name = exec.full_path().split('/')[-1]
        if want_tests != 'false'
                test('check-help-' + name,
                     check_help,
                     suite : 'dist-check',
                     args : exec.full_path(),
                     depends: exec)

                test('check-version-' + name,
                     check_version,
                     suite : 'dist-check',
                     args : [exec.full_path(),
                             meson.project_version()],
                     depends: exec)
        endif
endforeach

############################################################

check_directives_sh = find_program('tools/check-directives.sh')

if want_tests != 'false'
        test('check-directives',
             check_directives_sh,
             suite : 'dist-check',
             args : [project_source_root, project_build_root])
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
                                elif fuzz_tests
                                        exe = custom_target(
                                                name,
                                                output : name,
                                                depends : build,
                                                command : [ln, '-fs',
                                                           build.full_path() / b,
                                                           '@OUTPUT@'],
                                                build_by_default : true)
                                else
                                        message('Not compiling @0@ because fuzz-tests is set to false'.format(name))
                                endif
                        endif
                        prev = name

                        if fuzz_tests
                                test('@0@_@1@_@2@'.format(b, c, sanitizer),
                                     env,
                                     suite : 'fuzz+san',
                                     env : ['UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1'],
                                     timeout : 60,
                                     args : [exe.full_path(),
                                             project_source_root / p])
                        endif
                endforeach
        endif
endforeach


############################################################

if git.found()
        all_files = run_command(
                env, '-u', 'GIT_WORK_TREE',
                git, '--git-dir=@0@/.git'.format(project_source_root),
                     'ls-files', ':/*.[ch]',
                check : false)
        if all_files.returncode() == 0
                all_files = files(all_files.stdout().split())

                custom_target(
                        'tags',
                        output : 'tags',
                        command : [env, 'etags', '-o', '@0@/TAGS'.format(project_source_root)] + all_files)
                run_target(
                        'ctags',
                        command : [env, 'ctags', '--tag-relative=never', '-o', '@0@/tags'.format(project_source_root)] + all_files)
        endif
endif

if git.found()
        git_contrib_sh = find_program('tools/git-contrib.sh')
        run_target(
                'git-contrib',
                command : [git_contrib_sh])
endif

if git.found()
        git_head = run_command(
                git, '--git-dir=@0@/.git'.format(project_source_root),
                     'rev-parse', 'HEAD',
                check : false).stdout().strip()
        git_head_short = run_command(
                git, '--git-dir=@0@/.git'.format(project_source_root),
                     'rev-parse', '--short=7', 'HEAD',
                check : false).stdout().strip()

        run_target(
                'git-snapshot',
                command : [git, 'archive',
                           '-o', '@0@/systemd-@1@.tar.gz'.format(project_source_root,
                                                                 git_head_short),
                           '--prefix', 'systemd-@0@/'.format(git_head),
                           'HEAD'])
endif

############################################################

check_api_docs_sh = find_program('tools/check-api-docs.sh')
run_target(
        'check-api-docs',
        depends : [man, libsystemd, libudev],
        command : [check_api_docs_sh, libsystemd.full_path(), libudev.full_path()])

alias_target('update-dbus-docs', update_dbus_docs)
alias_target('update-man-rules', update_man_rules)

if not meson.is_cross_build()
        custom_target(
                'export-dbus-interfaces',
                output : fs.name(dbus_interfaces_dir),
                install : dbus_interfaces_dir != 'no',
                install_dir : fs.parent(dbus_interfaces_dir),
                command : [export_dbus_interfaces_py, '@OUTPUT@', dbus_programs])
endif

############################################################

alt_time_epoch = run_command('date', '-Is', '-u', '-d', '@@0@'.format(time_epoch),
                             check : true).stdout().strip()

summary({
        'split /usr' :                      split_usr,
        'split bin-sbin' :                  split_bin,
        'prefix directory' :                prefixdir,
        'rootprefix directory' :            rootprefixdir,
        'sysconf directory' :               sysconfdir,
        'include directory' :               includedir,
        'lib directory' :                   libdir,
        'rootlib directory' :               rootlibdir,
        'SysV init scripts' :               sysvinit_path,
        'SysV rc?.d directories' :          sysvrcnd_path,
        'PAM modules directory' :           pamlibdir,
        'PAM configuration directory' :     pamconfdir,
        'libcryptsetup plugins directory' : libcryptsetup_plugins_dir,
        'RPM macros directory' :            rpmmacrosdir,
        'modprobe.d directory' :            modprobedir,
        'D-Bus policy directory' :          dbuspolicydir,
        'D-Bus session directory' :         dbussessionservicedir,
        'D-Bus system directory' :          dbussystemservicedir,
        'D-Bus interfaces directory' :      dbus_interfaces_dir,
        'bash completions directory' :      bashcompletiondir,
        'zsh completions directory' :       zshcompletiondir,
        'private shared lib version tag' :  shared_lib_tag,
        'extra start script' :              get_option('rc-local'),
        'debug shell' :                     '@0@ @ @1@'.format(get_option('debug-shell'),
                                                               get_option('debug-tty')),
        'system UIDs' :                     '<=@0@ (alloc >=@1@)'.format(conf.get('SYSTEM_UID_MAX'),
                                                                         conf.get('SYSTEM_ALLOC_UID_MIN')),
        'system GIDs' :                     '<=@0@ (alloc >=@1@)'.format(conf.get('SYSTEM_GID_MAX'),
                                                                         conf.get('SYSTEM_ALLOC_GID_MIN')),
        'dynamic UIDs' :                    '@0@…@1@'.format(dynamic_uid_min, dynamic_uid_max),
        'container UID bases' :             '@0@…@1@'.format(container_uid_base_min, container_uid_base_max),
        'static UID/GID allocations' :      ' '.join(static_ugids),
        '/dev/kvm access mode' :            get_option('dev-kvm-mode'),
        'render group access mode' :        get_option('group-render-mode'),
        'certificate root directory' :      get_option('certificate-root'),
        'support URL' :                     support_url,
        'nobody user name' :                nobody_user,
        'nobody group name' :               nobody_group,
        'fallback hostname' :               get_option('fallback-hostname'),
        'default compression method' :      compression,
        'default DNSSEC mode' :             default_dnssec,
        'default DNS-over-TLS mode' :       default_dns_over_tls,
        'default mDNS mode' :               default_mdns,
        'default LLMNR mode' :              default_llmnr,
        'default DNS servers' :             dns_servers.split(' '),
        'default NTP servers' :             ntp_servers.split(' '),
        'default cgroup hierarchy' :        default_hierarchy,
        'default net.naming-scheme value' : default_net_naming_scheme,
        'default KillUserProcesses value' : kill_user_processes,
        'default locale' :                  default_locale,
        'default nspawn locale' :           nspawn_locale,
        'default status unit format' :      status_unit_format_default,
        'default user $PATH' :
                default_user_path != '' ? default_user_path : '(same as system services)',
        'systemd service watchdog' :        service_watchdog == '' ? 'disabled' : service_watchdog,
        'time epoch' :                      '@0@ (@1@)'.format(time_epoch, alt_time_epoch)})

# TODO:
# CFLAGS:   ${OUR_CFLAGS} ${CFLAGS}
# CPPFLAGS: ${OUR_CPPFLAGS} ${CPPFLAGS}
# LDFLAGS:  ${OUR_LDFLAGS} ${LDFLAGS}

found = []
missing = []

foreach tuple : [
        # dependencies
        ['ACL'],
        ['AUDIT'],
        ['AppArmor'],
        ['IMA'],
        ['PAM'],
        ['SECCOMP'],
        ['SELinux'],
        ['SMACK'],
        ['blkid'],
        ['elfutils'],
        ['gcrypt'],
        ['gnutls'],
        ['libbpf'],
        ['libcryptsetup'],
        ['libcryptsetup-plugins'],
        ['libcurl'],
        ['libfdisk'],
        ['libfido2'],
        ['libidn'],
        ['libidn2'],
        ['libiptc'],
        ['microhttpd'],
        ['openssl'],
        ['p11kit'],
        ['pcre2'],
        ['pwquality'],
        ['qrencode'],
        ['tpm2'],
        ['xkbcommon'],

        # compression libs
        ['zstd'],
        ['lz4'],
        ['xz'],
        ['zlib'],
        ['bzip2'],

        # components
        ['backlight'],
        ['binfmt'],
        ['bpf-framework',          conf.get('BPF_FRAMEWORK') == 1],
        ['coredump'],
        ['environment.d'],
        ['efi'],
        ['gnu-efi'],
        ['firstboot'],
        ['hibernate'],
        ['homed'],
        ['hostnamed'],
        ['hwdb'],
        ['importd'],
        ['initrd'],
        ['kernel-install'],
        ['localed'],
        ['logind'],
        ['machined'],
        ['networkd'],
        ['nss-myhostname'],
        ['nss-mymachines'],
        ['nss-resolve'],
        ['nss-systemd'],
        ['oomd'],
        ['portabled'],
        ['pstore'],
        ['quotacheck'],
        ['randomseed'],
        ['repart'],
        ['resolve'],
        ['rfkill'],
        ['sysext'],
        ['systemd-analyze',        conf.get('ENABLE_ANALYZE') == 1],
        ['sysupdate'],
        ['sysusers'],
        ['timedated'],
        ['timesyncd'],
        ['tmpfiles'],
        ['userdb'],
        ['vconsole'],
        ['xdg-autostart'],

        # optional features
        ['idn'],
        ['polkit'],
        ['nscd'],
        ['legacy-pkla',            install_polkit_pkla],
        ['kmod'],
        ['dbus'],
        ['glib'],
        ['tpm'],
        ['man pages',              want_man],
        ['html pages',             want_html],
        ['man page indices',       want_man and have_lxml],
        ['SysV compat'],
        ['compat-mutable-uid-boundaries'],
        ['utmp'],
        ['ldconfig'],
        ['adm group',              get_option('adm-group')],
        ['wheel group',            get_option('wheel-group')],
        ['gshadow'],
        ['debug hashmap'],
        ['debug mmap cache'],
        ['debug siphash'],
        ['valgrind',               conf.get('VALGRIND') == 1],
        ['trace logging',          conf.get('LOG_TRACE') == 1],
        ['install tests',          install_tests],
        ['link-udev-shared',       get_option('link-udev-shared')],
        ['link-systemctl-shared',  get_option('link-systemctl-shared')],
        ['link-networkd-shared',   get_option('link-networkd-shared')],
        ['link-timesyncd-shared',  get_option('link-timesyncd-shared')],
        ['link-journalctl-shared', get_option('link-journalctl-shared')],
        ['link-boot-shared',       get_option('link-boot-shared')],
        ['first-boot-full-preset'],
        ['fexecve'],
        ['standalone-binaries',    get_option('standalone-binaries')],
        ['coverage',               get_option('b_coverage')],
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

if static_libsystemd == 'false'
        missing += 'static-libsystemd'
else
        found += 'static-libsystemd(@0@)'.format(static_libsystemd)
endif

if static_libudev == 'false'
        missing += 'static-libudev'
else
        found += 'static-libudev(@0@)'.format(static_libudev)
endif

if conf.get('HAVE_OPENSSL_OR_GCRYPT') == 1 and conf.get('PREFER_OPENSSL') == 1
        found += 'cryptolib(openssl)'
elif conf.get('HAVE_OPENSSL_OR_GCRYPT') == 1
        found += 'cryptolib(gcrypt)'
else
        missing += 'cryptolib'
endif

if conf.get('DNS_OVER_TLS_USE_GNUTLS') == 1
        found += 'DNS-over-TLS(gnutls)'
elif conf.get('DNS_OVER_TLS_USE_OPENSSL') == 1
        found += 'DNS-over-TLS(openssl)'
else
        missing += 'DNS-over-TLS'
endif

summary({
        'enabled' :  ', '.join(found),
        'disabled' : ', '.join(missing)},
        section : 'Features')

if rootprefixdir != rootprefix_default
        warning('\n' +
                'Note that the installation prefix was changed to "@0@".\n'.format(rootprefixdir) +
                'systemd used fixed names for unit file directories and other paths, so anything\n' +
                'except the default ("@0@") is strongly discouraged.'.format(rootprefix_default))
endif

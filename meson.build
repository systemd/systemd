# SPDX-License-Identifier: LGPL-2.1-or-later

project('systemd', 'c',
        version : files('meson.version'),
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu17',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
                'warning_level=2',
        ],
        meson_version : '>= 0.62.0',
)

add_test_setup(
        'default',
        exclude_suites : ['clang-tidy', 'unused-symbols', 'integration-tests'],
        is_default : true,
)

project_major_version = meson.project_version().split('.')[0].split('~')[0]
if meson.project_version().contains('.')
        project_minor_version = meson.project_version().split('.')[-1].split('~')[0]
else
        project_minor_version = '0'
endif

libsystemd_version = '0.42.0'
libudev_version = '1.7.12'

conf = configuration_data()
conf.set_quoted('PROJECT_URL', 'https://systemd.io/')
conf.set('PROJECT_VERSION', project_major_version,
         description : 'Numerical project version (used where a simple number is expected)')
conf.set_quoted('PROJECT_VERSION_STR', project_major_version,
        description: 'Stringified project version (used where a simple string is expected)')
conf.set_quoted('PROJECT_VERSION_FULL', meson.project_version(), description : 'Full project version')

relative_source_path = run_command('realpath',
                                   '--relative-to=@0@'.format(meson.project_build_root()),
                                   meson.project_source_root(),
                                   check : true).stdout().strip()
conf.set_quoted('RELATIVE_SOURCE_PATH', relative_source_path)

conf.set10('BUILD_MODE_DEVELOPER', get_option('mode') == 'developer',
           description : 'tailor build to development or release builds')

feature = get_option('log-message-verification')
if feature.auto()
        have = conf.get('BUILD_MODE_DEVELOPER') == 1
else
        have = feature.enabled()
endif
conf.set10('LOG_MESSAGE_VERIFICATION', have)

want_ossfuzz = get_option('oss-fuzz')
want_libfuzzer = get_option('llvm-fuzz')
if want_ossfuzz and want_libfuzzer
        error('only one of oss-fuzz or llvm-fuzz can be specified')
endif

fuzzer_build = want_ossfuzz or want_libfuzzer

# If we're building *not* for actual fuzzing, allow input samples of any size
# (for testing and for reproduction of issues discovered with previously-higher
# limits).
conf.set10('FUZZ_USE_SIZE_LIMIT', fuzzer_build)

# We'll set this to '1' for EFI builds in a different place.
conf.set10('SD_BOOT', false)

# Create a title-less summary section early, so it ends up first in the output.
# More items are added later after they have been detected.
summary({
        'libc'       : get_option('libc'),
        'build mode' : get_option('mode'),
})

#####################################################################

fs = import('fs')
if get_option('split-bin') == 'auto'
        split_bin = not fs.is_symlink('/usr/sbin')
else
        split_bin = get_option('split-bin') == 'true'
endif
conf.set10('HAVE_SPLIT_BIN', split_bin,
           description : 'bin and sbin directories are separate')

have_standalone_binaries = get_option('standalone-binaries')

conf.set10('CREATE_LOG_DIRS', get_option('create-log-dirs'))

if get_option('hibernate') and not get_option('initrd')
        error('hibernate depends on initrd')
endif

conf.set10('BUMP_PROC_SYS_FS_FILE_MAX', get_option('bump-proc-sys-fs-file-max'))
conf.set10('BUMP_PROC_SYS_FS_NR_OPEN',  get_option('bump-proc-sys-fs-nr-open'))
conf.set('HIGH_RLIMIT_NOFILE',          512*1024)

conf.set('JOURNAL_STORAGE_DEFAULT',     get_option('journal-storage-default'))
conf.set('JOURNAL_STORAGE_DEFAULT_VAL', 'STORAGE_' + get_option('journal-storage-default').to_upper())

# Meson ignores the preceding arguments when joining paths if an absolute
# component is encountered, so this should canonicalize various paths when they
# are absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error(f'Prefix is not absolute: "@prefixdir@"')
endif

prefixdir_noslash = '/' + prefixdir.strip('/')
bindir = prefixdir / get_option('bindir')
sbindir = prefixdir / (split_bin ? 'sbin' : 'bin')
sbin_to_bin = split_bin ? '../bin/' : ''
libdir = prefixdir / get_option('libdir')
sysconfdir = prefixdir / get_option('sysconfdir')
includedir = prefixdir / get_option('includedir')
datadir = prefixdir / get_option('datadir')
localstatedir = '/' / get_option('localstatedir')

libexecdir = prefixdir / 'lib/systemd'
libexecdir_to_bin = '../../bin/'
pkglibdir = libdir / 'systemd'

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
modprobedir = prefixdir / 'lib/modprobe.d'

# Our own paths
pkgdatadir = datadir / 'systemd'
environmentdir = prefixdir / 'lib/environment.d'
pkgsysconfdir = sysconfdir / 'systemd'
userunitdir = libexecdir / 'user'
userpresetdir = libexecdir / 'user-preset'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'
usertmpfilesdir = prefixdir / 'share/user-tmpfiles.d'
sysusersdir = prefixdir / 'lib/sysusers.d'
sysctldir = prefixdir / 'lib/sysctl.d'
binfmtdir = prefixdir / 'lib/binfmt.d'
modulesloaddir = prefixdir / 'lib/modules-load.d'
networkdir = libexecdir / 'network'
systemgeneratordir = libexecdir / 'system-generators'
usergeneratordir = libexecdir / 'user-generators'
systemenvgeneratordir = libexecdir / 'system-environment-generators'
userenvgeneratordir = libexecdir / 'user-environment-generators'
systemshutdowndir = libexecdir / 'system-shutdown'
systemsleepdir = libexecdir / 'system-sleep'
systemunitdir = libexecdir / 'system'
systempresetdir = libexecdir / 'system-preset'
initrdpresetdir = libexecdir / 'initrd-preset'
udevlibexecdir = prefixdir / 'lib/udev'
udevrulesdir = udevlibexecdir / 'rules.d'
udevhwdbdir = udevlibexecdir / 'hwdb.d'
catalogdir = libexecdir / 'catalog'
kerneldir = prefixdir / 'lib/kernel'
kernelinstalldir = kerneldir / 'install.d'
factorydir = datadir / 'factory'
bootlibdir = libexecdir / 'boot/efi'
testsdir = libexecdir / 'tests'
unittestsdir = testsdir / 'unit-tests'
testdata_dir = testsdir / 'testdata'
systemdstatedir = localstatedir / 'lib/systemd'
catalogstatedir = systemdstatedir / 'catalog'
randomseeddir = localstatedir / 'lib/systemd'
systemprofiledir = libexecdir / 'portable' / 'profile'
userprofiledir = libexecdir / 'user' / 'portable' / 'profile'
repartdefinitionsdir = libexecdir / 'repart/definitions'
ntpservicelistdir = libexecdir / 'ntp-units.d'
credstoredir = prefixdir / 'lib/credstore'
pcrlockdir = prefixdir / 'lib/pcrlock.d'
mimepackagesdir = prefixdir / 'share/mime/packages'
varlinkbridgesdir = libexecdir / 'varlink-bridges'

configfiledir = get_option('configfiledir')
if configfiledir == ''
        configfiledir = sysconfdir
endif
pkgconfigfiledir = configfiledir / 'systemd'

docdir = get_option('docdir')
if docdir == ''
        docdir = datadir / 'doc/systemd'
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = libdir / 'security'
endif

pamconfdir = get_option('pamconfdir')
if pamconfdir == ''
        pamconfdir = prefixdir / 'lib/pam.d'
endif

sshconfdir = get_option('sshconfdir')
if sshconfdir == ''
        sshconfdir = sysconfdir / 'ssh/ssh_config.d'
endif
conf.set10('LINK_SSH_PROXY_DROPIN', sshconfdir != 'no' and not sshconfdir.startswith('/usr/'))

sshdconfdir = get_option('sshdconfdir')
if sshdconfdir == ''
        sshdconfdir = sysconfdir / 'ssh/sshd_config.d'
endif
conf.set10('LINK_SSHD_USERDB_DROPIN', sshdconfdir != 'no' and not sshdconfdir.startswith('/usr/'))

sshdprivsepdir = get_option('sshdprivsepdir')
conf.set10('CREATE_SSHDPRIVSEPDIR', sshdprivsepdir != 'no' and not sshdprivsepdir.startswith('/usr/'))
conf.set('SSHDPRIVSEPDIR', sshdprivsepdir, description : 'SSH privilege separation directory')

libcryptsetup_plugins_dir = get_option('libcryptsetup-plugins-dir')
if libcryptsetup_plugins_dir == ''
        libcryptsetup_plugins_dir = libdir / 'cryptsetup'
endif

shellprofiledir = get_option('shellprofiledir')
if shellprofiledir == ''
        shellprofiledir = sysconfdir / 'profile.d'
endif
conf.set10('LINK_SHELL_EXTRA_DROPIN', shellprofiledir != 'no' and not shellprofiledir.startswith('/usr/'))
conf.set10('LINK_OSC_CONTEXT_DROPIN', shellprofiledir != 'no' and not shellprofiledir.startswith('/usr/'))
conf.set('SHELLPROFILEDIR', shellprofiledir, description : 'shell profile directory')

memory_accounting_default = get_option('memory-accounting-default')
status_unit_format_default = get_option('status-unit-format-default')
if status_unit_format_default == 'auto'
        status_unit_format_default = conf.get('BUILD_MODE_DEVELOPER') == 1 ? 'name' : 'description'
endif

conf.set_quoted('BINDIR',                                     bindir)
conf.set_quoted('BINFMT_DIR',                                 binfmtdir)
conf.set_quoted('BOOTLIBDIR',                                 bootlibdir)
conf.set_quoted('CATALOG_DATABASE',                           catalogstatedir / 'database')
conf.set_quoted('CERTIFICATE_ROOT',                           get_option('certificate-root'))
conf.set_quoted('DOC_DIR',                                    docdir)
conf.set_quoted('DOCUMENT_ROOT',                              pkgdatadir / 'gatewayd')
conf.set_quoted('ENVIRONMENT_DIR',                            environmentdir)
conf.set_quoted('INCLUDE_DIR',                                includedir)
conf.set_quoted('LIBDIR',                                     libdir)
conf.set_quoted('LIBEXECDIR',                                 libexecdir)
conf.set_quoted('KERNEL_INSTALL_DIR',                         kernelinstalldir)
conf.set_quoted('MODPROBE_DIR',                               modprobedir)
conf.set_quoted('MODULESLOAD_DIR',                            modulesloaddir)
conf.set_quoted('PKGSYSCONFDIR',                              pkgsysconfdir)
conf.set_quoted('POLKIT_RULES_DIR',                           polkitrulesdir)
conf.set_quoted('PREFIX',                                     prefixdir)
conf.set_quoted('PREFIX_NOSLASH',                             prefixdir_noslash)
conf.set_quoted('RANDOM_SEED',                                randomseeddir / 'random-seed')
conf.set_quoted('RANDOM_SEED_DIR',                            randomseeddir)
conf.set_quoted('SSHCONFDIR',                                 sshconfdir)
conf.set_quoted('SSHDCONFDIR',                                sshdconfdir)
conf.set_quoted('SHELLPROFILEDIR',                            shellprofiledir)
conf.set_quoted('SYSCONF_DIR',                                sysconfdir)
conf.set_quoted('SYSCTL_DIR',                                 sysctldir)
conf.set_quoted('SYSTEMCTL_BINARY_PATH',                      bindir / 'systemctl')
conf.set_quoted('SYSTEMD_BINARY_PATH',                        libexecdir / 'systemd')
conf.set_quoted('SYSTEMD_EXECUTOR_BINARY_PATH',               libexecdir / 'systemd-executor')
conf.set_quoted('SYSTEMD_CATALOG_DIR',                        catalogdir)
conf.set_quoted('SYSTEMD_CRYPTSETUP_PATH',                    bindir / 'systemd-cryptsetup')
conf.set_quoted('SYSTEMD_EXPORT_PATH',                        libexecdir / 'systemd-export')
conf.set_quoted('SYSTEMD_FSCK_PATH',                          libexecdir / 'systemd-fsck')
conf.set_quoted('SYSTEMD_GROWFS_PATH',                        libexecdir / 'systemd-growfs')
conf.set_quoted('SYSTEMD_HOMEWORK_PATH',                      libexecdir / 'systemd-homework')
conf.set_quoted('SYSTEMD_IMPORT_FS_PATH',                     libexecdir / 'systemd-import-fs')
conf.set_quoted('SYSTEMD_IMPORT_PATH',                        libexecdir / 'systemd-import')
conf.set_quoted('SYSTEMD_INTEGRITYSETUP_PATH',                libexecdir / 'systemd-integritysetup')
conf.set_quoted('SYSTEMD_KBD_MODEL_MAP',                      pkgdatadir / 'kbd-model-map')
conf.set_quoted('SYSTEMD_LANGUAGE_FALLBACK_MAP',              pkgdatadir / 'language-fallback-map')
conf.set_quoted('SYSTEMD_MAKEFS_PATH',                        libexecdir / 'systemd-makefs')
conf.set_quoted('SYSTEMD_PULL_PATH',                          libexecdir / 'systemd-pull')
conf.set_quoted('SYSTEMD_SHUTDOWN_BINARY_PATH',               libexecdir / 'systemd-shutdown')
conf.set_quoted('SYSTEMD_SYSUPDATE_PATH',                     libexecdir / 'systemd-sysupdate')
conf.set_quoted('SYSTEMD_TEST_DATA',                          testdata_dir)
conf.set_quoted('SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH', bindir / 'systemd-tty-ask-password-agent')
conf.set_quoted('SYSTEMD_UPDATE_HELPER_PATH',                 libexecdir / 'systemd-update-helper')
conf.set_quoted('SYSTEMD_USERWORK_PATH',                      libexecdir / 'systemd-userwork')
conf.set_quoted('SYSTEMD_MOUNTWORK_PATH',                     libexecdir / 'systemd-mountwork')
conf.set_quoted('SYSTEMD_NSRESOURCEWORK_PATH',                libexecdir / 'systemd-nsresourcework')
conf.set_quoted('SYSTEMD_VERITYSETUP_PATH',                   libexecdir / 'systemd-veritysetup')
conf.set_quoted('SYSTEM_CONFIG_UNIT_DIR',                     pkgsysconfdir / 'system')
conf.set_quoted('SYSTEM_DATA_UNIT_DIR',                       systemunitdir)
conf.set_quoted('SYSTEM_ENV_GENERATOR_DIR',                   systemenvgeneratordir)
conf.set_quoted('SYSTEM_GENERATOR_DIR',                       systemgeneratordir)
conf.set_quoted('SYSTEM_PRESET_DIR',                          systempresetdir)
conf.set_quoted('SYSTEM_SHUTDOWN_PATH',                       systemshutdowndir)
conf.set_quoted('SYSTEM_SLEEP_PATH',                          systemsleepdir)
conf.set_quoted('SYSUSERS_DIR',                               sysusersdir)
conf.set_quoted('TMPFILES_DIR',                               tmpfilesdir)
conf.set_quoted('USER_TMPFILES_DIR',                          usertmpfilesdir)
conf.set_quoted('UDEVLIBEXECDIR',                             udevlibexecdir)
conf.set_quoted('UDEV_HWDB_DIR',                              udevhwdbdir)
conf.set_quoted('UDEV_RULES_DIR',                             udevrulesdir)
conf.set_quoted('USER_CONFIG_UNIT_DIR',                       pkgsysconfdir / 'user')
conf.set_quoted('USER_DATA_UNIT_DIR',                         userunitdir)
conf.set_quoted('USER_ENV_GENERATOR_DIR',                     userenvgeneratordir)
conf.set_quoted('USER_GENERATOR_DIR',                         usergeneratordir)
conf.set_quoted('USER_KEYRING_PATH',                          pkgsysconfdir / 'import-pubring.pgp')
conf.set_quoted('USER_KEYRING_PATH_LEGACY',                   pkgsysconfdir / 'import-pubring.gpg')
conf.set_quoted('USER_PRESET_DIR',                            userpresetdir)
conf.set_quoted('VARLINK_BRIDGES_DIR',                        varlinkbridgesdir)
conf.set_quoted('VENDOR_KEYRING_PATH',                        libexecdir / 'import-pubring.pgp')

conf.set('ANSI_OK_COLOR',                                     'ANSI_' + get_option('ok-color').underscorify().to_upper())
conf.set10('ENABLE_URLIFY',                                   get_option('urlify'))
conf.set10('ENABLE_FEXECVE',                                  get_option('fexecve'))
conf.set10('MEMORY_ACCOUNTING_DEFAULT',                       memory_accounting_default)
conf.set('STATUS_UNIT_FORMAT_DEFAULT',                        'STATUS_UNIT_FORMAT_' + status_unit_format_default.to_upper())
conf.set_quoted('STATUS_UNIT_FORMAT_DEFAULT_STR',             status_unit_format_default)

conf.set('DEFAULT_TIMEOUT_SEC',                               get_option('default-timeout-sec'))
conf.set('DEFAULT_USER_TIMEOUT_SEC',                          get_option('default-user-timeout-sec'))
conf.set('UPDATE_HELPER_USER_TIMEOUT_SEC',                    get_option('update-helper-user-timeout-sec'))

conf.set10('ENABLE_FIRST_BOOT_FULL_PRESET',                   get_option('first-boot-full-preset'))

#####################################################################

cc = meson.get_compiler('c')
userspace_c_args = []
userspace_c_ld_args = []
userspace_sources = []

want_tests = get_option('tests')
want_slow_tests = want_tests != 'false' and get_option('slow-tests')
want_fuzz_tests = want_tests != 'false' and get_option('fuzz-tests')
install_tests = want_tests != 'false' and get_option('install-tests')

if add_languages('cpp', native : false, required : fuzzer_build)
        #  Used only for tests
        cxx = meson.get_compiler('cpp')
        cxx_cmd = ' '.join(cxx.cmd_array())
else
        cxx_cmd = ''
endif

if want_libfuzzer
        if cc.has_argument('-fsanitize=fuzzer-no-link')
                userspace_c_args += '-fsanitize=fuzzer-no-link'
        else
                error('Looks like -fsanitize=fuzzer-no-link is not supported')
        endif
elif want_ossfuzz
        fuzzing_engine = meson.get_compiler('cpp').find_library('FuzzingEngine')
endif

# Those generate many false positives, and we do not want to change the code to
# avoid them.
basic_disabled_warnings = [
        '-Wno-missing-field-initializers',
        '-Wno-unknown-warning-option',
        '-Wno-unused-parameter',
        '-Wno-nonnull-compare',
]

possible_common_cc_flags = [
        '-Warray-bounds',     # clang
        '-Warray-bounds=2',
        '-Wdate-time',
        '-Wendif-labels',
        '-Werror=bool-compare',
        '-Werror=discarded-qualifiers',
        '-Werror=flex-array-member-not-at-end',
        '-Werror=format=2',
        '-Werror=format-signedness',
        '-Werror=implicit-function-declaration',
        '-Werror=implicit-int',
        '-Werror=incompatible-pointer-types',
        '-Werror=int-conversion',
        '-Werror=missing-declarations',
        '-Werror=missing-parameter-name',
        '-Werror=missing-prototypes',
        '-Werror=overflow',
        '-Werror=override-init',
        '-Werror=pointer-sign',
        '-Werror=return-type',
        '-Werror=sequence-point',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Werror=strict-flex-arrays',
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
        '-Wunterminated-string-initialization',
        '-Wunused-function',
        '-Wwrite-strings',
        '-Wzero-as-null-pointer-constant',
        '-Wzero-length-bounds',

        # negative arguments are correctly detected starting with meson 0.46.
        '-Wno-error=#warnings',  # clang
        '-Wno-string-plus-int',  # clang

        '-fdiagnostics-show-option',
        '-fno-common',
        '-fstack-protector',
        '-fstack-protector-strong',
        '-fstrict-flex-arrays=3',
        '--param=ssp-buffer-size=4',
]

possible_common_link_flags = [
        '-fstack-protector',
]

c_args = get_option('c_args')

# Our json library does not support -ffinite-math-only, which is enabled by -Ofast or -ffast-math.
have = false
foreach arg : c_args
        if arg in ['-ffinite-math-only', '-ffast-math', '-Ofast']
                have = true
        elif arg in ['-fno-finite-math-only', '-fno-fast-math']
                have = false
        endif
endforeach
if have
        error('-ffinite-math-only is enabled (may be implied by -ffast-math or -Ofast) in c_args.')
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
                             '-Og' in c_args or
                             '-Ofast' in c_args)
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
        '-Wl,-z,gcs-report-dynamic=none',
        '-Wl,--gc-sections',
]

if get_option('b_sanitize') == 'none'
        possible_link_flags += '-Wl,--warn-common'
endif

if get_option('mode') == 'release'
        # We could enable 'pattern' for developer mode, but that can interfere with
        # valgrind and sanitizer builds. Also, clang does not zero-initialize unions,
        # breaking some of our code (https://reviews.llvm.org/D68115).
        possible_common_cc_flags += '-ftrivial-auto-var-init=zero'
endif

possible_cc_flags = [
        '-fno-strict-aliasing',
        '-fstrict-flex-arrays=1',
        '-fvisibility=hidden',
]

if get_option('mode') == 'developer'
        possible_cc_flags += '-fno-omit-frame-pointer'
endif

add_project_arguments(
        cc.get_supported_arguments(
                basic_disabled_warnings,
                possible_common_cc_flags
        ),
        language : 'c')

add_project_link_arguments(
        cc.get_supported_link_arguments(possible_common_link_flags),
        language : 'c')

userspace_c_args += cc.get_supported_arguments(possible_cc_flags)
userspace_c_ld_args += cc.get_supported_link_arguments(possible_link_flags)

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

cpp = ' '.join(cc.cmd_array() + get_option('c_args')) + ' -E'

# new in GCC 10
have = cc.has_argument('-Wzero-length-bounds')
conf.set10('HAVE_WARNING_ZERO_LENGTH_BOUNDS', have)

# new in GCC 15
have = cc.has_argument('-Wzero-as-null-pointer-constant')
conf.set10('HAVE_WARNING_ZERO_AS_NULL_POINTER_CONSTANT', have)

#####################################################################
# compilation result tests

conf.set('_GNU_SOURCE', 1)
conf.set('__SANE_USERSPACE_TYPES__', true)

# glibc always defines _LARGEFILE64_SOURCE when _GNU_SOURCE is set, but musl does not do that,
# and it is necessary for making getdents64() and struct dirent64 exist.
conf.set('_LARGEFILE64_SOURCE', 1)

conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_TIMEX_MEMBER', cc.sizeof('typeof(((struct timex *)0)->freq)', prefix : '#include <sys/timex.h>'))

long_max = cc.compute_int(
        'LONG_MAX',
        prefix : '#include <limits.h>',
        guess : 0x7FFFFFFFFFFFFFFF,
        high : 0x7FFFFFFFFFFFFFFF)
assert(long_max > 100000)
conf.set_quoted('LONG_MAX_STR', f'@long_max@')

foreach ident : [
        ['renameat2',         '''#include <stdio.h>'''],        # since musl-1.2.6
        ['set_mempolicy',     '''#include <sys/syscall.h>'''],  # declared at numaif.h provided by libnuma, which we do not use
        ['get_mempolicy',     '''#include <sys/syscall.h>'''],  # declared at numaif.h provided by libnuma, which we do not use
        ['epoll_pwait2',      '''#include <sys/epoll.h>'''],    # since glibc-2.35
        ['fsconfig',          '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['fsmount',           '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['fsopen',            '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['mount_setattr',     '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['move_mount',        '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['open_tree',         '''#include <sys/mount.h>'''],    # since glibc-2.36
        ['pidfd_open',        '''#include <sys/pidfd.h>'''],    # since glibc-2.36
        ['pidfd_send_signal', '''#include <sys/pidfd.h>'''],    # since glibc-2.36
        ['pidfd_spawn',       '''#include <spawn.h>'''],        # since glibc-2.39
        ['sched_setattr',     '''#include <sched.h>'''],        # since glibc-2.41
        ['ioprio_get',        '''#include <sched.h>'''],        # no known header declares ioprio_get
        ['ioprio_set',        '''#include <sched.h>'''],        # no known header declares ioprio_set
        ['rt_tgsigqueueinfo', '''#include <signal.h>'''],       # no known header declares rt_tgsigqueueinfo
        ['open_tree_attr',    '''#include <sys/mount.h>'''],    # no known header declares open_tree_attr
        ['quotactl_fd',       '''#include <sys/quota.h>'''],    # no known header declares quotactl_fd
        ['fchmodat2',         '''#include <sys/stat.h>'''],     # no known header declares fchmodat2
        ['bpf',               '''#include <sys/syscall.h>'''],  # no known header declares bpf
        ['kcmp',              '''#include <sys/syscall.h>'''],  # no known header declares kcmp
        ['keyctl',            '''#include <sys/syscall.h>'''],  # no known header declares keyctl
        ['add_key',           '''#include <sys/syscall.h>'''],  # no known header declares add_key
        ['request_key',       '''#include <sys/syscall.h>'''],  # no known header declares request_key
        ['setxattrat',        '''#include <sys/xattr.h>'''],    # no known header declares setxattrat
        ['removexattrat',     '''#include <sys/xattr.h>'''],    # no known header declares removexattrat
        ['pivot_root',        '''#include <unistd.h>'''],       # no known header declares pivot_root
]

        have = cc.has_function(ident[0], prefix : ident[1], args : '-D_GNU_SOURCE')
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

#####################################################################

awk    = find_program('awk')
diff   = find_program('diff')
echo   = find_program('echo')
env    = find_program('env')
find   = find_program('find')
getent = find_program('getent', required : false)
git    = find_program('git', required : false)
gperf  = find_program('gperf')
id     = find_program('id', required : false)
ln     = find_program('ln')
rsync  = find_program('rsync', required : false)
sed    = find_program('sed')
sh     = find_program('sh')
stat   = find_program('stat')

ln_s = ln.full_path() + ' -frsT -- "${DESTDIR:-}@0@" "${DESTDIR:-}@1@"'

# If -Dxxx-path option is found, use that. Otherwise, use the default from the
# middle column; a full path is used directly, a relative path is converted to
# /usr/bin/foo or /usr/sbin/foo, depending on whether split-bin is enabled.
progs = [['quotaon',    'quotaon'              ],
         ['quotacheck', 'quotacheck'           ],
         ['kmod',       '/usr/bin/kmod'        ],
         ['kexec',      'kexec'                ],
         ['sulogin',    'sulogin'              ],
         ['swapon',     'swapon'               ],
         ['swapoff',    'swapoff'              ],
         ['agetty',     'agetty'               ],
         ['mount',      '/usr/bin/mount',      'MOUNT_PATH'],
         ['umount',     '/usr/bin/umount',     'UMOUNT_PATH'],
         ['loadkeys',   '/usr/bin/loadkeys',   'KBD_LOADKEYS'],
         ['setfont',    '/usr/bin/setfont',    'KBD_SETFONT'],
         ['nologin',    'nologin',             ],
        ]
foreach prog : progs
        path = get_option(prog[0] + '-path')
        if path == ''
                if prog[1].startswith('/')
                        path = prog[1]
                else
                        path = '/usr' / (split_bin ? 'sbin' : 'bin') / prog[1]
                endif
        endif
        message('Using @1@ for @0@'.format(prog[0], path))

        name = prog.length() > 2 ? prog[2] : prog[0].to_upper()
        conf.set_quoted(name, path)
endforeach

#####################################################################

gperf_test_format = '''
#include <string.h>
const char* in_word_set(const char *, @0@);
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
message(f'gperf len type is @gperf_len_type@')
conf.set('GPERF_LEN_TYPE', gperf_len_type,
         description : 'The type of gperf "len" parameter')

#####################################################################

foreach header : [
        'sys/sdt.h',
        'threads.h',
        'valgrind/memcheck.h',
        'valgrind/valgrind.h',
]

        conf.set10('HAVE_' + header.underscorify().to_upper(),
                   cc.has_header(header))
endforeach

foreach ident : [
                ['NI_IDN', 'netdb.h']
        ]

        if meson.version().version_compare('>=1.3.0')
                have = cc.has_define(ident[0],
                                     prefix : '''#include <@0@>'''.format(ident[1]),
                                     args : '-D_GNU_SOURCE')
        else
                have = cc.has_header_symbol(ident[1], ident[0])
        endif
        conf.set10('HAVE_' + ident[0], have)
endforeach

#####################################################################

fallback_hostname = get_option('fallback-hostname')
if fallback_hostname == '' or fallback_hostname[0] == '.' or fallback_hostname[0] == '-'
        error('Invalid fallback-hostname configuration')
        # A more extensive test is done in test-hostname-util. Let's catch
        # the most obvious errors here so we don't fail with an assert later.
endif
conf.set_quoted('FALLBACK_HOSTNAME', fallback_hostname)

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
conf.set_quoted('DEFAULT_NET_NAMING_SCHEME', default_net_naming_scheme,
                description : 'Default naming scheme as a string')
if default_net_naming_scheme != 'latest'
        conf.set('_DEFAULT_NET_NAMING_SCHEME',
                 'NAMING_' + default_net_naming_scheme.underscorify().to_upper(),
                 description : 'Default naming scheme as a constant')
endif

time_epoch = get_option('time-epoch')
if time_epoch <= 0
        time_epoch = run_command(sh, '-c', 'echo "$SOURCE_DATE_EPOCH"', check : true).stdout().strip()
        if time_epoch == '' and git.found() and fs.is_dir('.git')
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
                                         check : false)
                if time_epoch.returncode() != 0
                        # If the above fails, maybe the stat(1) uses BSD-style syntax
                        time_epoch = run_command(stat, '-f', '%m', NEWS,
                                                 check : true)
                endif
                time_epoch = time_epoch.stdout()
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

greeter_uid_min = get_option('greeter-uid-min')
greeter_uid_max = get_option('greeter-uid-max')
conf.set('GREETER_UID_MIN', greeter_uid_min)
conf.set('GREETER_UID_MAX', greeter_uid_max)

dynamic_uid_min = get_option('dynamic-uid-min')
dynamic_uid_max = get_option('dynamic-uid-max')
conf.set('DYNAMIC_UID_MIN', dynamic_uid_min)
conf.set('DYNAMIC_UID_MAX', dynamic_uid_max)

container_uid_base_min = get_option('container-uid-base-min')
container_uid_base_max = get_option('container-uid-base-max')
conf.set('CONTAINER_UID_BASE_MIN', container_uid_base_min)
conf.set('CONTAINER_UID_BASE_MAX', container_uid_base_max)

foreign_uid_base = get_option('foreign-uid-base')
conf.set('FOREIGN_UID_BASE', foreign_uid_base)

nobody_user = get_option('nobody-user')
nobody_group = get_option('nobody-group')

if not meson.is_cross_build()
        if getent.found()
                ret = run_command(getent, 'passwd', '65534', check : false)
                if ret.returncode() == 0
                        name = ret.stdout().split(':')[0]
                        if name != nobody_user
                                warning('\n' +
                                        f'The local user with the UID 65534 does not match the configured user name "@nobody_user@" of the nobody user (its name is @name@).\n' +
                                        'Your build will result in an user table setup that is incompatible with the local system.')
                        endif
                endif
        endif
        if id.found()
                ret = run_command(id, '-u', nobody_user, check : false)
                if ret.returncode() == 0
                        uid = ret.stdout().strip().to_int()
                        if uid != 65534
                                warning('\n' +
                                        f'The local user with the configured user name "@nobody_user@" of the nobody user does not have UID 65534 (it has @uid@).\n' +
                                        'Your build will result in an user table setup that is incompatible with the local system.')
                        endif
                endif
        endif

        if getent.found()
                ret = run_command(getent, 'group', '65534', check : false)
                if ret.returncode() == 0
                        name = ret.stdout().split(':')[0]
                        if name != nobody_group
                                warning('\n' +
                                        f'The local group with the GID 65534 does not match the configured group name "@nobody_group@" of the nobody group (its name is @name@).\n' +
                                        'Your build will result in an group table setup that is incompatible with the local system.')
                        endif
                endif
        endif
        if id.found()
                ret = run_command(id, '-g', nobody_group, check : false)
                if ret.returncode() == 0
                        gid = ret.stdout().strip().to_int()
                        if gid != 65534
                                warning('\n' +
                                        f'The local group with the configured group name "@nobody_group@" of the nobody group does not have GID 65534 (it has @gid@).\n' +
                                        'Your build will result in an group table setup that is incompatible with the local system.')
                        endif
                endif
        endif
endif
if nobody_user != nobody_group and not (nobody_user == 'nobody' and nobody_group == 'nogroup')
        warning('\n' +
                f'The configured user name "@nobody_user@" and group name "@nobody_group@" of the nobody user/group are not equivalent.\n' +
                'Please re-check that both "nobody-user" and "nobody-group" options are correctly set.')
endif

conf.set_quoted('NOBODY_USER_NAME', nobody_user)
conf.set_quoted('NOBODY_GROUP_NAME', nobody_group)

static_ugids = []
foreach option : ['adm-gid',
                  'audio-gid',
                  'cdrom-gid',
                  'clock-gid',
                  'dialout-gid',
                  'disk-gid',
                  'empower-gid',
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

        # Ensure provided GID argument is positive, otherwise fall back to default assignment
        conf.set(name, val > 0 ? val : '-')
        if val > 0
                static_ugids += f'@option@:@val@'
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
tty_mode = get_option('tty-mode')
# The setting is used as both octal integer and string through STRINGIFY().
# Here, only check if the value starts with '06', and further check will be done in terminal-util.h.
if not tty_mode.startswith('06')
        error(f'Unexpected access mode "@tty_mode@" is specified for TTY/PTS device nodes, it must be "06xx"')
elif tty_mode != '0600' and tty_mode != '0620'
        warning(f'Unexpected access mode "@tty_mode@" is specified for TTY/PTS device nodes, typically it should be "0600" or "0620", proceeding anyway')
endif
# Do not use set_quoted() here, so that the value is available as an integer.
conf.set('TTY_MODE', tty_mode)

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

default_keymap = get_option('default-keymap')
if default_keymap == ''
        # We canonicalize empty keymap to '@kernel', as it makes the default value
        # in the factory provided /etc/vconsole.conf more obvious.
        default_keymap = '@kernel'
endif
conf.set_quoted('SYSTEMD_DEFAULT_KEYMAP', default_keymap)

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
                message(f'unknown debug option "@name@", ignoring')
        endif
endforeach
conf.set10('ENABLE_DEBUG_HASHMAP', enable_debug_hashmap)
conf.set10('ENABLE_DEBUG_MMAP_CACHE', enable_debug_mmap_cache)
conf.set10('ENABLE_DEBUG_SIPHASH', enable_debug_siphash)
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

# On some distributions that use musl (e.g. Alpine), libintl.h may be provided by gettext rather than musl.
# In that case, we need to explicitly link with libintl.so.
if cc.has_function('dgettext',
                   prefix : '''#include <libintl.h>''',
                   args : '-D_GNU_SOURCE')
        libintl = []
else
        libintl = cc.find_library('intl')
        if not cc.has_function('dgettext',
                               prefix : '''#include <libintl.h>''',
                               args : '-D_GNU_SOURCE',
                               dependencies : libintl)
                error('dgettext() not found')
        endif
endif

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

if get_option('libc') == 'musl'
        libcrypt = []
        libcrypt_cflags = []
        have = get_option('libcrypt').allowed()
else
        libcrypt = dependency('libcrypt', 'libxcrypt',
                              required : get_option('libcrypt'),
                              version : '>=4.4.0')
        libcrypt_cflags = libcrypt.partial_dependency(includes: true, compile_args: true)
        have = libcrypt.found()
endif
conf.set10('HAVE_LIBCRYPT', have)

bpf_framework = get_option('bpf-framework')
bpf_compiler = get_option('bpf-compiler')
libbpf = dependency('libbpf',
                    required : bpf_framework,
                    version : bpf_compiler == 'gcc' ? '>= 1.4.0' : '>= 0.1.0')
libbpf_cflags = libbpf.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_LIBBPF', libbpf.found())

if not libbpf.found()
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
                        r = find_program('clang',
                                         required : bpf_framework,
                                         version : '>= 10.0.0')
                        clang_found = r.found()
                        if clang_found
                                clang = r.full_path()
                        endif
                else
                        clang_found = true
                        clang = cc.cmd_array()
                endif

                if clang_found
                        # Check if 'clang -target bpf' is supported.
                        clang_supports_bpf = run_command(clang, '-target', 'bpf', '--print-supported-cpus', check : false).returncode() == 0
                endif
                if bpf_framework.enabled() and not clang_supports_bpf
                        error('bpf-framework was enabled but clang does not support bpf')
                endif
        elif bpf_compiler == 'gcc'
                bpf_gcc = find_program('bpf-gcc',
                                       'bpf-none-gcc',
                                       'bpf-unknown-none-gcc',
                                       required : true,
                                       version : '>= 13.1.0')
                bpf_gcc_found = bpf_gcc.found()
        endif

        if clang_supports_bpf or bpf_gcc_found
                # Debian installs this in /usr/sbin/ which is not in $PATH.
                # We check for 'bpftool' first, honouring $PATH, and in /usr/sbin/ for Debian.
                # We use 'bpftool gen object' subcommand for bpftool strip, it was added by d80b2fcbe0a023619e0fc73112f2a02c2662f6ab (v5.13).
                bpftool = find_program('bpftool',
                                       '/usr/sbin/bpftool',
                                       required : bpf_framework.enabled() and bpf_compiler == 'gcc',
                                       version : bpf_compiler == 'gcc' ? '>= 7.0.0' : '>= 5.13.0')

                if bpftool.found()
                        bpftool_strip = true
                        deps_found = true
                elif bpf_compiler == 'clang'
                        # We require the 'bpftool gen skeleton' subcommand, it was added by 985ead416df39d6fe8e89580cc1db6aa273e0175 (v5.6).
                        bpftool = find_program('bpftool',
                                               '/usr/sbin/bpftool',
                                               required : bpf_framework,
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
                        llvm_strip = find_program(llvm_strip_bin,
                                                  required : bpf_framework,
                                                  version : '>= 10.0.0')
                        deps_found = llvm_strip.found()
                endif
        endif

        # Can build BPF program from source code in restricted C
        conf.set10('BPF_FRAMEWORK', deps_found)
endif

libmount = dependency('mount',
                      version : fuzzer_build ? '>= 0' : '>= 2.30',
                      required : get_option('libmount'))
have = libmount.found()
conf.set10('HAVE_LIBMOUNT', have)
libmount_cflags = libmount.partial_dependency(includes: true, compile_args: true)

libfdisk = dependency('fdisk',
                      version : '>= 2.32',
                      disabler : true,
                      required : get_option('fdisk'))
conf.set10('HAVE_LIBFDISK', libfdisk.found())

# This prefers pwquality if both are enabled or auto.
feature = get_option('pwquality').disable_auto_if(get_option('passwdqc').enabled())
libpwquality = dependency('pwquality',
                          version : '>= 1.4.1',
                          required : feature)
have = libpwquality.found()
if not have
        # libpwquality is used for both features for simplicity
        libpwquality = dependency('passwdqc',
                                  required : get_option('passwdqc'))
endif
libpwquality_cflags = libpwquality.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_PWQUALITY', have)
conf.set10('HAVE_PASSWDQC', not have and libpwquality.found())

libseccomp = dependency('libseccomp',
                        version : '>= 2.4.0',
                        required : get_option('seccomp'))
conf.set10('HAVE_SECCOMP', libseccomp.found())
libseccomp_cflags = libseccomp.partial_dependency(includes: true, compile_args: true)

libselinux = dependency('libselinux',
                        version : '>= 2.1.9',
                        required : get_option('selinux'))
conf.set10('HAVE_SELINUX', libselinux.found())
libselinux_cflags = libselinux.partial_dependency(includes: true, compile_args: true)

libapparmor = dependency('libapparmor',
                         version : '>= 2.13',
                         required : get_option('apparmor'))
conf.set10('HAVE_APPARMOR', libapparmor.found())
libapparmor_cflags = libapparmor.partial_dependency(includes: true, compile_args: true)

have = get_option('smack') and get_option('smack-run-label') != ''
conf.set10('HAVE_SMACK_RUN_LABEL', have)
if have
        conf.set_quoted('SMACK_RUN_LABEL', get_option('smack-run-label'))
endif

have = get_option('smack') and get_option('smack-default-process-label') != ''
if have
        conf.set_quoted('SMACK_DEFAULT_PROCESS_LABEL', get_option('smack-default-process-label'))
endif

feature = get_option('polkit')
libpolkit = dependency('polkit-gobject-1',
                       required : feature.disabled() ? feature : false)
install_polkit = feature.allowed()
install_polkit_pkla = libpolkit.found() and libpolkit.version().version_compare('< 0.106')
if install_polkit_pkla
        message('Old polkit detected, will install pkla files')
endif
conf.set10('ENABLE_POLKIT', install_polkit)

libacl = dependency('libacl',
                    required : get_option('acl'))
conf.set10('HAVE_ACL', libacl.found())
libacl_cflags = libacl.partial_dependency(includes: true, compile_args: true)

libaudit = dependency('audit',
                      required : get_option('audit'))
conf.set10('HAVE_AUDIT', libaudit.found())
libaudit_cflags = libaudit.partial_dependency(includes: true, compile_args: true)

libblkid = dependency('blkid',
                      version : '>=2.37.0',
                      required : get_option('blkid'))
conf.set10('HAVE_BLKID', libblkid.found())
libblkid_cflags = libblkid.partial_dependency(includes: true, compile_args: true)

libkmod = dependency('libkmod',
                     version : '>= 15',
                     required : get_option('kmod'))
conf.set10('HAVE_KMOD', libkmod.found())
libkmod_cflags = libkmod.partial_dependency(includes: true, compile_args: true)

libxenctrl = dependency('xencontrol',
                        version : '>= 4.9',
                        required : get_option('xenctrl'))
conf.set10('HAVE_XENCTRL', libxenctrl.found())
libxenctrl_cflags = libxenctrl.partial_dependency(includes: true, compile_args: true)

feature = get_option('pam')
libpam = dependency('pam',
                    required : feature.disabled() ? feature : false)
if not libpam.found()
        # Debian older than bookworm and Ubuntu older than 22.10 do not provide the .pc file.
        libpam = cc.find_library('pam', required : feature)
endif
libpam_misc = dependency('pam_misc',
                         required : feature.disabled() ? feature : false)
if not libpam_misc.found()
        libpam_misc = cc.find_library('pam_misc', required : feature)
endif
conf.set10('HAVE_PAM', libpam.found() and libpam_misc.found())
libpam_cflags = libpam.partial_dependency(includes: true, compile_args: true)

libmicrohttpd = dependency('libmicrohttpd',
                           version : '>= 0.9.33',
                           required : get_option('microhttpd'))
conf.set10('HAVE_MICROHTTPD', libmicrohttpd.found())

libcryptsetup = get_option('libcryptsetup')
libcryptsetup_plugins = get_option('libcryptsetup-plugins')
if libcryptsetup_plugins.enabled()
        if libcryptsetup.disabled()
                error('libcryptsetup-plugins cannot be requested without libcryptsetup')
        endif
        libcryptsetup = libcryptsetup_plugins
endif

libcryptsetup = dependency('libcryptsetup',
                           version : '>= 2.4.0',
                           required : libcryptsetup)
libcryptsetup_cflags = libcryptsetup.partial_dependency(includes: true, compile_args: true)

have = libcryptsetup.found()
conf.set10('HAVE_LIBCRYPTSETUP', have)
conf.set10('HAVE_LIBCRYPTSETUP_PLUGINS',
           libcryptsetup_plugins.allowed() and have)

foreach ident : [
                'crypt_set_keyring_to_link',     # 2.7
                'crypt_token_set_external_path', # 2.7
        ]

        have_ident = have and cc.has_function(
                ident,
                prefix : '#include <libcryptsetup.h>',
                dependencies : libcryptsetup)
        conf.set10('HAVE_' + ident.to_upper(), have_ident)
endforeach

libcurl = dependency('libcurl',
                     version : '>= 7.32.0',
                     required : get_option('libcurl'))
conf.set10('HAVE_LIBCURL', libcurl.found())
conf.set10('CURL_NO_OLDIES', conf.get('BUILD_MODE_DEVELOPER') == 1)

libidn2 = dependency('libidn2',
                     required : get_option('libidn2'))
libidn2_cflags = libidn2.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_LIBIDN2', libidn2.found())

libqrencode = dependency('libqrencode',
                         version : '>= 3',
                         required : get_option('qrencode'))
libqrencode_cflags = libqrencode.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_QRENCODE', libqrencode.found())

feature = get_option('gcrypt')
libgcrypt = dependency('libgcrypt',
                       required : feature)
libgpg_error = dependency('gpg-error',
                          required : feature)

have = libgcrypt.found() and libgpg_error.found()
if not have
        # link to neither of the libs if one is not found
        libgcrypt = []
        libgpg_error = []
        libgcrypt_cflags = []
else
        libgcrypt_cflags = libgcrypt.partial_dependency(includes: true, compile_args: true)
endif
conf.set10('HAVE_GCRYPT', have)

libgnutls = dependency('gnutls',
                       version : '>= 3.1.4',
                       required : get_option('gnutls'))
conf.set10('HAVE_GNUTLS', libgnutls.found())

libopenssl = dependency('openssl',
                        version : '>= 3.0.0',
                        required : get_option('openssl'))
conf.set10('HAVE_OPENSSL', libopenssl.found())

libp11kit = dependency('p11-kit-1',
                       version : '>= 0.23.3',
                       required : get_option('p11kit'))
conf.set10('HAVE_P11KIT', libp11kit.found())
libp11kit_cflags = libp11kit.partial_dependency(includes: true, compile_args: true)

feature = get_option('libfido2').require(
        conf.get('HAVE_OPENSSL') == 1,
        error_message : 'openssl required')
libfido2 = dependency('libfido2',
                      required : feature)
libfido2_cflags = libfido2.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_LIBFIDO2', libfido2.found())

tpm2 = dependency('tss2-esys tss2-rc tss2-mu tss2-tcti-device',
                  required : get_option('tpm2'))
tpm2_cflags = tpm2.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_TPM2', tpm2.found())
conf.set10('HAVE_TSS2_ESYS3', tpm2.found() and tpm2.version().version_compare('>= 3.0.0'))
conf.set('TPM2_NVPCR_BASE', get_option('tpm2-nvpcr-base'))

libdw = dependency('libdw',
                   version : '>=0.177',
                   required : get_option('elfutils'))
libdw_cflags = libdw.partial_dependency(includes: true, compile_args: true)
libelf = dependency('libelf',
                    required : get_option('elfutils'))
libelf_cflags = libelf.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_ELFUTILS', libdw.found() and libelf.found())

# New in elfutils 0.192
conf.set10('HAVE_DWFL_SET_SYSROOT',
           libdw.found() and cc.has_function('dwfl_set_sysroot', dependencies : libdw))

libz = dependency('zlib',
                  required : get_option('zlib'))
conf.set10('HAVE_ZLIB', libz.found())

feature = get_option('bzip2')
libbzip2 = dependency('bzip2',
                      required : feature.disabled() ? feature : false)
if not libbzip2.found()
        # Debian and Ubuntu do not provide the .pc file.
        libbzip2 = cc.find_library('bz2', required : feature)
endif
conf.set10('HAVE_BZIP2', libbzip2.found())

libxz = dependency('liblzma',
                   required : get_option('xz'))
conf.set10('HAVE_XZ', libxz.found())
libxz_cflags = libxz.partial_dependency(includes: true, compile_args: true)

liblz4 = dependency('liblz4',
                    version : '>= 1.3.0',
                    required : get_option('lz4'))
conf.set10('HAVE_LZ4', liblz4.found())
liblz4_cflags = liblz4.partial_dependency(includes: true, compile_args: true)

libzstd = dependency('libzstd',
                     version : '>= 1.4.0',
                     required : get_option('zstd'))
conf.set10('HAVE_ZSTD', libzstd.found())
libzstd_cflags = libzstd.partial_dependency(includes: true, compile_args: true)

conf.set10('HAVE_COMPRESSION', libxz.found() or liblz4.found() or libzstd.found())

compression = get_option('default-compression')
if compression == 'auto'
        if libzstd.found()
                compression = 'zstd'
        elif liblz4.found()
                compression = 'lz4'
        elif libxz.found()
                compression = 'xz'
        else
                compression = 'none'
        endif
elif compression == 'zstd' and not libzstd.found()
        error('default-compression=zstd requires zstd')
elif compression == 'lz4' and not liblz4.found()
        error('default-compression=lz4 requires lz4')
elif compression == 'xz' and not libxz.found()
        error('default-compression=xz requires xz')
endif
# In the dlopen ELF note we save the default compression library with a
# higher priority, so that packages can give it priority over the
# secondary libraries.
conf.set_quoted('COMPRESSION_PRIORITY_ZSTD',
                compression == 'zstd' ? 'recommended' : 'suggested')
conf.set_quoted('COMPRESSION_PRIORITY_LZ4',
                compression == 'lz4' ? 'recommended' : 'suggested')
conf.set_quoted('COMPRESSION_PRIORITY_XZ',
                compression == 'xz' ? 'recommended' : 'suggested')
conf.set('DEFAULT_COMPRESSION', 'COMPRESSION_@0@'.format(compression.to_upper()))

libarchive = dependency('libarchive',
                        version : '>= 3.0',
                        required : get_option('libarchive'))
libarchive_cflags = libarchive.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_LIBARCHIVE', libarchive.found())

foreach ident : [
                'archive_entry_gid_is_set',      # since 3.7.3
                'archive_entry_uid_is_set',      # since 3.7.3
                'archive_entry_hardlink_is_set', # since 3.7.5
        ]

        have = libarchive.found() and cc.has_function(ident, dependencies : libarchive)
        conf.set10('HAVE_' + ident.to_upper(), have)
endforeach

libxkbcommon = dependency('xkbcommon',
                          version : '>= 0.3.0',
                          required : get_option('xkbcommon'))
libxkbcommon_cflags = libxkbcommon.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_XKBCOMMON', libxkbcommon.found())

libpcre2 = dependency('libpcre2-8',
                      required : get_option('pcre2'))
libpcre2_cflags = libpcre2.partial_dependency(includes: true, compile_args: true)
conf.set10('HAVE_PCRE2', libpcre2.found())

libglib =    dependency('glib-2.0',
                        version : '>= 2.22.0',
                        required : get_option('glib'))
libgobject = dependency('gobject-2.0',
                        version : '>= 2.22.0',
                        required : get_option('glib'))
libgio =     dependency('gio-2.0',
                        required : get_option('glib'))
conf.set10('HAVE_GLIB', libglib.found() and libgobject.found() and libgio.found())

libdbus = dependency('dbus-1',
                     version : '>= 1.3.2',
                     required : get_option('dbus'))
conf.set10('HAVE_DBUS', libdbus.found())

dbusdatadir = libdbus.get_variable(pkgconfig: 'datadir', default_value: datadir) / 'dbus-1'

dbuspolicydir = get_option('dbuspolicydir')
if dbuspolicydir == ''
        dbuspolicydir = dbusdatadir / 'system.d'
endif

dbussessionservicedir = get_option('dbussessionservicedir')
if dbussessionservicedir == ''
        dbussessionservicedir = libdbus.get_variable(pkgconfig: 'session_bus_services_dir', default_value: dbusdatadir / 'services')
endif

dbussystemservicedir = get_option('dbussystemservicedir')
if dbussystemservicedir == ''
        dbussystemservicedir = libdbus.get_variable(pkgconfig: 'system_bus_services_dir', default_value: dbusdatadir / 'system-services')
endif

dbus_interfaces_dir = get_option('dbus-interfaces-dir')
if dbus_interfaces_dir == '' or dbus_interfaces_dir == 'yes'
        if meson.is_cross_build() and dbus_interfaces_dir != 'yes'
                dbus_interfaces_dir = 'no'
                warning('Exporting D-Bus interface XML files is disabled during cross build. Pass path or "yes" to force enable.')
        else
                dbus_interfaces_dir = libdbus.get_variable(pkgconfig: 'interfaces_dir', default_value: dbusdatadir / 'interfaces')
        endif
endif

dmi_arches = ['x86', 'x86_64', 'aarch64', 'arm', 'ia64', 'loongarch64', 'mips', 'riscv64']
conf.set10('HAVE_DMI', host_machine.cpu_family() in dmi_arches)

dns_over_tls = get_option('dns-over-tls')
have_openssl = conf.get('HAVE_OPENSSL') == 1
if dns_over_tls == 'false'
        have = false
elif dns_over_tls == 'auto'
        have = have_openssl
elif have_openssl
        have = true
else
        error('DNS-over-TLS support was requested, but OpenSSL support is disabled.')
endif
conf.set10('ENABLE_DNS_OVER_TLS', have)

default_dns_over_tls = get_option('default-dns-over-tls')
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

have = get_option('repart').require(
        conf.get('HAVE_LIBFDISK') == 1,
        error_message : 'fdisk required').allowed()
conf.set10('ENABLE_REPART', have)

default_dnssec = get_option('default-dnssec')
if default_dnssec != 'no' and conf.get('HAVE_OPENSSL') == 0
        message('default-dnssec cannot be set to yes or allow-downgrade when openssl is disabled. Setting default-dnssec to no.')
        default_dnssec = 'no'
endif
conf.set('DEFAULT_DNSSEC_MODE',
         'DNSSEC_' + default_dnssec.underscorify().to_upper())
conf.set_quoted('DEFAULT_DNSSEC_MODE_STR', default_dnssec)

have = get_option('importd').require(
        conf.get('HAVE_LIBCURL') == 1 and
        conf.get('HAVE_OPENSSL') == 1 and
        conf.get('HAVE_ZLIB') == 1 and
        conf.get('HAVE_XZ') == 1,
        error_message : 'curl, openssl, zlib and xz required').allowed()
conf.set10('ENABLE_IMPORTD', have)

have = get_option('sysupdate').require(
        conf.get('ENABLE_IMPORTD') == 1 and
        conf.get('HAVE_OPENSSL') == 1 and
        conf.get('HAVE_LIBFDISK') == 1,
        error_message : 'systemd-importd, fdisk, and openssl required').allowed()
conf.set10('ENABLE_SYSUPDATE', have)

have2 = get_option('sysupdated')
if have2 == 'enabled'
        if have
                have2 = true
        else
                error('sysupdated requires sysupdate to be enabled')
        endif
elif have2 == 'auto'
        have2 = have and conf.get('BUILD_MODE_DEVELOPER') == 1
else
        have2 = false
endif
conf.set10('ENABLE_SYSUPDATED', have2)

conf.set10('ENABLE_STORAGETM', get_option('storagetm'))

have = get_option('homed').require(
        conf.get('HAVE_LIBCRYPT') == 1 and
        conf.get('HAVE_OPENSSL') == 1 and
        conf.get('HAVE_LIBFDISK') == 1 and
        conf.get('HAVE_LIBCRYPTSETUP') == 1,
        error_message : 'libcrypt, openssl, fdisk, and libcryptsetup required').allowed()
conf.set10('ENABLE_HOMED', have)

have = have and conf.get('HAVE_PAM') == 1
conf.set10('ENABLE_PAM_HOME', have)

feature = get_option('remote')
if feature.enabled()
        if conf.get('HAVE_MICROHTTPD') != 1
                error('remote support was requested, but microhttpd is not available')
        endif
        if conf.get('HAVE_LIBCURL') != 1
                error('remote support was requested, but libcurl is not available')
        endif
endif
# A more minimal version of systemd-journal-remote can always be built, even if neither
# libcurl nor microhttpd are available.
conf.set10('ENABLE_REMOTE', feature.allowed())

feature = get_option('vmspawn').disable_auto_if(conf.get('BUILD_MODE_DEVELOPER') == 0)
conf.set10('ENABLE_VMSPAWN', feature.allowed())

feature = get_option('nspawn')
conf.set10('ENABLE_NSPAWN', feature.allowed())

conf.set10('DEFAULT_MOUNTFSD_TRUSTED_DIRECTORIES', get_option('default-mountfsd-trusted-directories'))

foreach tuple : [
                ['analyze'],
                ['backlight'],
                ['binfmt'],
                ['compat-mutable-uid-boundaries'],
                ['compat-sysv-interfaces'],
                ['coredump'],
                ['efi'],
                ['environment-d'],
                ['firstboot'],
                ['gshadow',         get_option('libc') != 'musl', 'musl does not support it'],
                ['hibernate'],
                ['hostnamed'],
                ['hwdb'],
                ['idn',             conf.get('HAVE_NI_IDN') == 1, 'NI_IDN is not defined'],
                ['ima'],
                ['ipe'],
                ['initrd'],
                ['kernel-install'],
                ['ldconfig'],
                ['localed'],
                ['logind'],
                ['machined'],
                ['mountfsd'],
                ['networkd'],
                ['nsresourced'],
                ['nss-myhostname',  get_option('libc') != 'musl', 'musl does not support it'],
                ['nss-systemd',     get_option('libc') != 'musl', 'musl does not support it'],
                ['oomd'],
                ['portabled'],
                ['pstore'],
                ['quotacheck'],
                ['randomseed'],
                ['resolve'],
                ['rfkill'],
                ['smack'],
                ['sysext'],
                ['sysusers'],
                ['timedated'],
                ['timesyncd'],
                ['tmpfiles'],
                ['tpm'],
                ['utmp',            get_option('libc') != 'musl', 'musl does not support it'],
                ['userdb'],
                ['vconsole'],
                ['xdg-autostart'],
        ]

        have = get_option(tuple[0])
        if have and tuple.length() >= 3 and not tuple[1]
                warning('@0@ support is requested but @1@, disabling it'.format(tuple[0], tuple[2]))
                have = false
        endif

        name = 'ENABLE_' + tuple[0].underscorify().to_upper()
        conf.set10(name, have)
endforeach

enable_sysusers = conf.get('ENABLE_SYSUSERS') == 1

foreach tuple : [['nss-mymachines', 'machined'],
                 ['nss-resolve',    'resolve']]
        want = get_option(tuple[0])
        if want.enabled()
                if get_option('libc') == 'musl'
                        error('@0@ is requested but musl does not support it'.format(tuple[0]))
                endif
                if not get_option(tuple[1])
                        error('@0@ is requested but @1@ is disabled'.format(tuple[0], tuple[1]))
                endif
                have = true
        elif want.allowed()
                have = get_option(tuple[1]) and get_option('libc') != 'musl'
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

conf.set10('ENABLE_SSH_PROXY_CONFIG', sshconfdir != 'no')
conf.set10('ENABLE_SSH_USERDB_CONFIG', conf.get('ENABLE_USERDB') == 1 and sshdconfdir != 'no')

conf.set10('SYSTEMD_SLOW_TESTS_DEFAULT', want_slow_tests)

#####################################################################

pymod = import('python')
python = pymod.find_installation('python3', required : true, modules : ['jinja2'])
if not python.language_version().version_compare('>=3.9')
        error('Python >= 3.9 is required')
endif

#####################################################################

if conf.get('BPF_FRAMEWORK') == 1
        bpf_clang_flags = [
                '-std=gnu17',
                '-Wno-compare-distinct-pointer-types',
                '-Wno-microsoft-anon-tag',
                '-fms-extensions',
                '-fno-stack-protector',
                '-O2',
                '-target',
                'bpf',
                '-g',
                '-c',
        ]

        bpf_gcc_flags = [
                '-std=gnu17',
                '-fms-extensions',
                '-fno-stack-protector',
                '-fno-ssa-phiopt',
                '-O2',
                '-mcpu=v3',
                '-mco-re',
                '-gbtf',
                '-c',
        ]

        # If c_args contains these flags copy them along with the values, in order to avoid breaking
        # reproducible builds and other functionality
        propagate_cflags = [
                '-ffile-prefix-map=',
                '-fdebug-prefix-map=',
                '-fmacro-prefix-map=',
                '--sysroot=',
        ]

        foreach opt : c_args
                foreach flag : propagate_cflags
                        if opt.startswith(flag)
                                bpf_clang_flags += [opt]
                                bpf_gcc_flags += [opt]
                                break
                        endif
                endforeach
        endforeach

        # Generate defines that are appropriate to tell the compiler what architecture
        # we're compiling for. By default we just map meson's cpu_family to __<cpu_family>__.
        # This dictionary contains the exceptions where this doesn't work.
        #
        # C.f. https://mesonbuild.com/Reference-tables.html#cpu-families
        # and src/basic/missing_syscall_def.h.

        # Start with older ABI. When define is missing, we're likely targeting that.
        ppc64_elf_version = '1'

        if host_machine.cpu_family() == 'ppc64'
                # cc doesn't have to be bpf_compiler, but they should be targeting the same ABI
                call_elf_value = cc.get_define('_CALL_ELF')
                if call_elf_value != ''
                        ppc64_elf_version = call_elf_value
                endif
        endif

        cpu_arch_defines = {
                'ppc'         : ['-D__powerpc__', '-D__TARGET_ARCH_powerpc'],
                'ppc64'       : ['-D__powerpc64__', '-D__TARGET_ARCH_powerpc', '-D_CALL_ELF=' + ppc64_elf_version],
                'riscv32'     : ['-D__riscv', '-D__riscv_xlen=32', '-D__TARGET_ARCH_riscv'],
                'riscv64'     : ['-D__riscv', '-D__riscv_xlen=64', '-D__TARGET_ARCH_riscv'],
                'x86'         : ['-D__i386__', '-D__TARGET_ARCH_x86'],
                's390x'       : ['-D__s390__', '-D__s390x__', '-D__TARGET_ARCH_s390'],

                # For arm, assume hardware fp is available.
                'arm'         : ['-D__arm__', '-D__ARM_PCS_VFP', '-D__TARGET_ARCH_arm'],
                'loongarch64' : ['-D__loongarch__', '-D__loongarch_grlen=64', '-D__TARGET_ARCH_loongarch']
        }

        bpf_arch_flags = cpu_arch_defines.get(host_machine.cpu_family(),
                                              ['-D__@0@__'.format(host_machine.cpu_family())])
        if bpf_compiler == 'gcc'
                bpf_arch_flags += ['-m' + host_machine.endian() + '-endian']
        endif

        libbpf_include_dir = libbpf.get_variable(pkgconfig : 'includedir')

        bpf_o_unstripped_cmd = []
        if bpf_compiler == 'clang'
                bpf_o_unstripped_cmd += [
                        clang,
                        bpf_clang_flags,
                        bpf_arch_flags,
                ]
        elif bpf_compiler == 'gcc'
                bpf_o_unstripped_cmd += [
                        bpf_gcc,
                        bpf_gcc_flags,
                        bpf_arch_flags,
                ]
        endif

        bpf_o_unstripped_cmd += ['-I.']

        if cc.get_id() == 'gcc' or meson.is_cross_build()
                if cc.get_id() != 'gcc'
                        warning('Cross compiler is not gcc. Guessing the target triplet for bpf likely fails.')
                endif
                target_triplet_cmd = run_command(cc.cmd_array(), '-print-multiarch', check: false)
        else
                # clang does not support -print-multiarch (D133170) and its -dump-machine
                # does not match multiarch. Query gcc instead.
                target_triplet_cmd = run_command('gcc', '-print-multiarch', check: false)
        endif
        if target_triplet_cmd.returncode() == 0
                sysroot = meson.get_external_property('sys_root', '/')
                target_triplet = target_triplet_cmd.stdout().strip()
                target_include_dir = sysroot / 'usr' / 'include'
                target_triple_include_dir = target_include_dir / target_triplet
                isystem_dir = ''
                if fs.is_dir(target_triple_include_dir)
                        isystem_dir = target_triple_include_dir
                elif fs.is_dir(target_include_dir)
                        isystem_dir = target_include_dir
                endif
                if isystem_dir != ''
                        bpf_o_unstripped_cmd += [
                                '-isystem', isystem_dir
                        ]
                endif
        endif

        bpf_o_unstripped_cmd += [
                '-idirafter',
                libbpf_include_dir,
                '@INPUT@',
                '-o',
                '@OUTPUT@'
        ]

        if bpftool_strip
                bpf_o_cmd = [
                        bpftool,
                        'gen',
                        'object',
                        '@OUTPUT@',
                        '@INPUT@'
                ]
        elif bpf_compiler == 'clang'
                bpf_o_cmd = [
                        llvm_strip,
                        '-g',
                        '@INPUT@',
                        '-o',
                        '@OUTPUT@'
                ]
        endif

        skel_h_cmd = [
                bpftool,
                'gen',
                'skeleton',
                '@INPUT@'
        ]
endif

#####################################################################

efi_arch = {
        'aarch64'     : 'aa64',
        'arm'         : 'arm',
        'loongarch32' : 'loongarch32',
        'loongarch64' : 'loongarch64',
        'riscv32'     : 'riscv32',
        'riscv64'     : 'riscv64',
        'x86_64'      : 'x64',
        'x86'         : 'ia32',
}.get(host_machine.cpu_family(), '')

pyelftools = pymod.find_installation('python3',
                                     required : get_option('bootloader'),
                                     modules : ['elftools'])

have = get_option('bootloader').require(
        pyelftools.found() and get_option('efi') and efi_arch != '',
        error_message : 'unsupported EFI arch or EFI support is disabled').allowed()
conf.set10('ENABLE_BOOTLOADER', have)
conf.set_quoted('EFI_MACHINE_TYPE_NAME', have ? efi_arch : '')

efi_arch_alt = ''
efi_cpu_family_alt = ''
if have and efi_arch == 'x64' and cc.links('''
                #include <limits.h>
                int main(int argc, char *argv[]) {
                        return __builtin_popcount(argc - CHAR_MAX);
                }''', args : ['-m32', '-march=i686'], name : '32bit build possible')
        efi_arch_alt = 'ia32'
        efi_cpu_family_alt = 'x86'
endif

want_ukify = pymod.find_installation('python3', required: get_option('ukify'), modules : ['pefile']).found()
conf.set10('ENABLE_UKIFY', want_ukify)

#####################################################################

use_provided_vmlinux_h = false
use_generated_vmlinux_h = false
provided_vmlinux_h_path = get_option('vmlinux-h-path')

# For the more complex BPF programs we really want a vmlinux.h (which is arch
# specific, but only somewhat bound to kernel version). Ideally the kernel
# development headers would ship that, but right now they don't. Hence address
# this in two ways:
#
# 1. Provide a vmlinux.h at build time
# 2. Generate the file on the fly where possible (which requires /sys/ to be mounted)
#
# We generally prefer the former (to support reproducible builds), but will
# fallback to the latter.

if conf.get('BPF_FRAMEWORK') == 1
        enable_vmlinux_h = get_option('vmlinux-h')

        if enable_vmlinux_h == 'auto'
                if provided_vmlinux_h_path != ''
                        use_provided_vmlinux_h = true
                elif fs.exists('/sys/kernel/btf/vmlinux') and \
                                bpftool.found() and \
                                (host_machine.cpu_family() == build_machine.cpu_family()) and \
                                host_machine.cpu_family() in ['x86_64', 'aarch64']

                        # We will only generate a vmlinux.h from the running
                        # kernel if the host and build machine are of the same
                        # family. Also for now we focus on x86_64 and aarch64,
                        # since other archs don't seem to be ready yet.

                        use_generated_vmlinux_h = true
                endif
        elif enable_vmlinux_h == 'provided'
                use_provided_vmlinux_h = true
        elif enable_vmlinux_h == 'generated'
                if not fs.exists('/sys/kernel/btf/vmlinux')
                        error('BTF data from kernel not available (/sys/kernel/btf/vmlinux missing), cannot generate vmlinux.h, but was asked to.')
                endif
                if not bpftool.found()
                        error('bpftool not available, cannot generate vmlinux.h, but was asked to.')
                endif
                use_generated_vmlinux_h = true
        endif
endif

vmlinux_h_dependency = []
if use_provided_vmlinux_h
        if not fs.exists(provided_vmlinux_h_path)
                error('Path to provided vmlinux.h does not exist.')
        endif
        bpf_o_unstripped_cmd += ['-I' + fs.parent(provided_vmlinux_h_path)]
        message(f'Using provided @provided_vmlinux_h_path@')
elif use_generated_vmlinux_h
        vmlinux_h_dependency = custom_target(
                output: 'vmlinux.h',
                command : [ bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c' ],
                capture : true)

        bpf_o_unstripped_cmd += ['-I' + fs.parent(vmlinux_h_dependency.full_path())]
        message('Using generated @0@'.format(vmlinux_h_dependency.full_path()))
else
        message('Using neither provided nor generated vmlinux.h, some features will not be available.')
endif

conf.set10('HAVE_VMLINUX_H', use_provided_vmlinux_h or use_generated_vmlinux_h)

conf.set10('ENABLE_SYSCTL_BPF', conf.get('HAVE_VMLINUX_H') == 1 and libbpf.version().version_compare('>= 0.7'))

#####################################################################

version_tag = get_option('version-tag')
if version_tag == ''
        version_tag = meson.project_version()
endif

conf.set_quoted('VERSION_TAG', version_tag)

subdir('tools')
subdir('src/version')

shared_lib_tag = get_option('shared-lib-tag')
if shared_lib_tag == ''
        shared_lib_tag = project_major_version
endif

#####################################################################

subdir('src/coverage')

#####################################################################

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

userspace_c_args += ['-include', 'config.h']

jinja2_cmdline = [meson_render_jinja2_py, config_h]

userspace = declare_dependency(
        compile_args : userspace_c_args,
        link_args : userspace_c_ld_args,
        sources : userspace_sources,
)

man_page_depends = []

#####################################################################

simple_tests = []
libsystemd_tests = []
simple_fuzzers = []
catalogs = []
modules = [] # nss, pam, and other plugins
executables = []
executables_by_name = {}
objects_by_name = {}
fuzzer_exes = []
generated_sources = [version_h, vmlinux_h_dependency]
sources = []

# binaries that have --help and are intended for use by humans,
# usually, but not always, installed in /bin.
public_programs = []

# D-Bus introspection XML export
dbus_programs = []

# A list of boot stubs. Required for testing of ukify.
boot_stubs = []

# This is similar to system_includes below, but for passing custom_target().
system_include_args = [
        '-isystem', meson.project_build_root()  / 'src/include/override',
        '-isystem', meson.project_source_root() / 'src/include/override',
        '-isystem', meson.project_build_root()  / 'src/include/uapi',
        '-isystem', meson.project_source_root() / 'src/include/uapi',
]

system_includes = [
        include_directories(
                # gcc(1) says
                # "Directories specified with -isystem options are scanned in left-to-right order",
                # and meson puts the directories in the reversed order. Hence, a directory with a lower
                # priority must be listed earlier.
                'src/include/uapi',
                'src/include/override',
                is_system : true,
        ),
]

if get_option('libc') == 'musl'
        system_include_args = [
                '-isystem', meson.project_build_root()  / 'src/include/musl',
                '-isystem', meson.project_source_root() / 'src/include/musl',
        ] + system_include_args

        system_includes += include_directories('src/include/musl', is_system : true)
endif

basic_includes = [
        include_directories(
                'src/basic',
                'src/fundamental',
                'src/systemd',
        ),
        system_includes,
        version_include,
]

libsystemd_includes = [basic_includes, include_directories(
        'src/libsystemd/sd-bus',
        'src/libsystemd/sd-common',
        'src/libsystemd/sd-device',
        'src/libsystemd/sd-event',
        'src/libsystemd/sd-hwdb',
        'src/libsystemd/sd-id128',
        'src/libsystemd/sd-journal',
        'src/libsystemd/sd-json',
        'src/libsystemd/sd-netlink',
        'src/libsystemd/sd-network',
        'src/libsystemd/sd-path',
        'src/libsystemd/sd-resolve',
        'src/libsystemd/sd-varlink')]

includes = [libsystemd_includes, include_directories('src/shared')]

subdir('po')
subdir('catalog')
subdir('src/include')
subdir('src/libc')
subdir('src/fundamental')
subdir('src/basic')
subdir('src/libsystemd')
subdir('src/shared')
subdir('src/libudev')

libsystemd = shared_library(
        'systemd',
        version : libsystemd_version,
        include_directories : libsystemd_includes,
        implicit_include_directories : false,
        link_args : ['-shared',
                     # Make sure our library is never deleted from memory, so that our open logging fds don't leak on dlopen/dlclose cycles.
                     '-z', 'nodelete',
                     '-Wl,--version-script=' + libsystemd_sym_path],
        link_with : [libc_wrapper_static,
                     libbasic_static],
        link_whole : [libsystemd_static],
        dependencies : [librt,
                        threads,
                        userspace],
        link_depends : libsystemd_sym,
        install : true,
        install_tag: 'libsystemd',
        install_dir : libdir)

if static_libsystemd != 'false'
        install_libsystemd_static = static_library(
                'systemd',
                libc_wrapper_sources,
                libsystemd_sources,
                basic_sources,
                fundamental_sources,
                include_directories : libsystemd_includes,
                implicit_include_directories : false,
                install : true,
                install_tag: 'libsystemd',
                install_dir : libdir,
                pic : static_libsystemd_pic,
                dependencies : [libdl,
                                libgcrypt_cflags,
                                liblz4_cflags,
                                libm,
                                librt,
                                libxz_cflags,
                                libzstd_cflags,
                                threads,
                                userspace],
                c_args : libsystemd_c_args + (static_libsystemd_pic ? [] : ['-fno-PIC']))

        alias_target('libsystemd', libsystemd, install_libsystemd_static)
else
        alias_target('libsystemd', libsystemd)
endif

libudev = shared_library(
        'udev',
        version : libudev_version,
        include_directories : includes,
        implicit_include_directories : false,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libudev_sym_path],
        link_with : [libsystemd_static],
        link_whole : libudev_basic,
        dependencies : [threads,
                        userspace],
        link_depends : libudev_sym,
        install : true,
        install_tag: 'libudev',
        install_dir : libdir)

if static_libudev != 'false'
        install_libudev_static = static_library(
                'udev',
                libc_wrapper_sources,
                basic_sources,
                fundamental_sources,
                shared_sources,
                libsystemd_sources,
                libudev_sources,
                include_directories : includes,
                implicit_include_directories : false,
                install : true,
                install_tag: 'libudev',
                install_dir : libdir,
                link_depends : libudev_sym,
                dependencies : [libmount,
                                libshared_deps,
                                userspace],
                c_args : static_libudev_pic ? [] : ['-fno-PIC'],
                pic : static_libudev_pic)

        alias_target('libudev', libudev, install_libudev_static)
else
        alias_target('libudev', libudev)
endif

#####################################################################

runtest_env = custom_target(
        output : 'systemd-runtest.env',
        command : ['printf',
                   'SYSTEMD_TEST_DATA=%q\nSYSTEMD_CATALOG_DIR=%q\n',
                   meson.project_source_root() / 'test',
                   meson.project_build_root() / 'catalog'],
        capture: true,
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

#####################################################################

executable_template = {
        'include_directories' : includes,
        'link_with' : libshared,
        'install_rpath' : pkglibdir,
        'install' : true,
}

generator_template = executable_template + {
        'install_dir' : systemgeneratordir,
}

libexec_template = executable_template + {
        'install_dir' : libexecdir,
}

executable_additional_kwargs = {
        'dependencies' : userspace,
}

test_template = executable_template + {
        'build_by_default' : want_tests != 'false',
        'install' : install_tests,
        'install_dir' : unittestsdir,
}

test_additional_kwargs = {
        'c_args' : test_cflags,
        'link_depends' : runtest_env,
}

fuzz_template = executable_template + {
        'build_by_default' : want_fuzz_tests,
        'install' : false,
}

if want_ossfuzz
        fuzz_additional_kwargs = {
                'dependencies' : fuzzing_engine,
        }
elif want_libfuzzer
        fuzz_additional_kwargs = {
                'link_args' : ['-fsanitize=fuzzer'],
        }
else
        fuzz_additional_kwargs = {
                'sources' : files('src/fuzz/fuzz-main.c'),
        }
endif
fuzz_additional_kwargs += {
        'c_args' : test_cflags,
}

nss_template = {
        'version' : '2',
        'include_directories' : includes,
        # Note that we link NSS modules with '-z nodelete' so that mempools never get orphaned
        'link_args' : ['-z', 'nodelete'],
        'link_with' : [
                libc_wrapper_static,
                libsystemd_static,
                libshared_static,
                libbasic_static,
        ],
        'dependencies' : [
                librt,
                threads,
        ],
        'install' : true,
        'install_tag' : 'nss',
        'install_dir' : libdir,
}

pam_template = {
        'name_prefix' : '',
        'include_directories' : includes,
        'link_with' : [
                libsystemd_static,
                libshared_static,
        ],
        'dependencies' : [
                # Note: our PAM modules also call dlopen_libpam() and use
                # symbols acquired through that, hence the explicit dep here is
                # strictly speaking unnecessary. We put it in place anyway,
                # since for the PAM modules we cannot avoid libpam anyway,
                # after all they are loaded *by* libpam, and hence there's no
                # loss in having explicit deps here, but there's a win: it
                # makes the deps more visible.
                #
                # (In case you wonder why we do dlopen_libpam() from the PAM
                # modules in the first place: that's mostly so that all our PAM
                # code (regardless if our PAM modules or our PAM consuming
                # programs) can use the same helpers, which hence go via
                # dlopen_libpam().
                libpam_misc,
                libpam,
                threads,
        ],
        'install' : true,
        'install_tag' : 'pam',
        'install_dir' : pamlibdir,
}

module_additional_kwargs = {
        'link_args' : ['-shared'],
        'dependencies' : userspace,
}

#####################################################################

# systemd-analyze requires 'libcore'
subdir('src/core')
# systemd-networkd requires 'libsystemd_network'
subdir('src/libsystemd-network')
# hwdb requires 'udev_link_with' and 'udev_rpath'
subdir('src/udev')

subdir('src/ac-power')
subdir('src/analyze')
subdir('src/ask-password')
subdir('src/backlight')
subdir('src/battery-check')
subdir('src/binfmt')
subdir('src/bless-boot')
subdir('src/boot')
subdir('src/bootctl')
subdir('src/busctl')
subdir('src/cgls')
subdir('src/cgtop')
subdir('src/coredump')
subdir('src/creds')
subdir('src/cryptenroll')
subdir('src/cryptsetup')
subdir('src/debug-generator')
subdir('src/delta')
subdir('src/detect-virt')
subdir('src/dissect')
subdir('src/environment-d-generator')
subdir('src/escape')
subdir('src/factory-reset')
subdir('src/firstboot')
subdir('src/fsck')
subdir('src/fstab-generator')
subdir('src/getty-generator')
subdir('src/gpt-auto-generator')
subdir('src/growfs')
subdir('src/hibernate-resume')
subdir('src/home')
subdir('src/hostname')
subdir('src/hwdb')
subdir('src/id128')
subdir('src/import')
subdir('src/integritysetup')
subdir('src/journal')
subdir('src/journal-remote')
subdir('src/kernel-install')
subdir('src/keyutil')
subdir('src/locale')
subdir('src/login')
subdir('src/machine')
subdir('src/machine-id-setup')
subdir('src/measure')
subdir('src/modules-load')
subdir('src/mount')
subdir('src/mountfsd')
subdir('src/mstack')
subdir('src/mute-console')
subdir('src/network')
subdir('src/notify')
subdir('src/nspawn')
subdir('src/nsresourced')
subdir('src/nss-myhostname')
subdir('src/nss-mymachines')
subdir('src/nss-resolve')
subdir('src/nss-systemd')
subdir('src/oom')
subdir('src/path')
subdir('src/pcrextend')
subdir('src/pcrlock')
subdir('src/portable')
subdir('src/pstore')
subdir('src/ptyfwd')
subdir('src/quotacheck')
subdir('src/random-seed')
subdir('src/remount-fs')
subdir('src/repart')
subdir('src/report')
subdir('src/reply-password')
subdir('src/resolve')
subdir('src/rfkill')
subdir('src/rpm')
subdir('src/run')
subdir('src/run-generator')
subdir('src/sbsign')
subdir('src/shutdown')
subdir('src/sleep')
subdir('src/socket-activate')
subdir('src/socket-proxy')
subdir('src/ssh-generator')
subdir('src/stdio-bridge')
subdir('src/storagetm')
subdir('src/sulogin-shell')
subdir('src/sysctl')
subdir('src/sysext')
subdir('src/system-update-generator')
subdir('src/systemctl')
subdir('src/sysupdate')
subdir('src/sysusers')
subdir('src/timedate')
subdir('src/timesync')
subdir('src/tmpfiles')
subdir('src/tpm2-setup')
subdir('src/tty-ask-password-agent')
subdir('src/update-done')
subdir('src/update-utmp')
subdir('src/user-sessions')
subdir('src/userdb')
subdir('src/validatefs')
subdir('src/varlinkctl')
subdir('src/vconsole')
subdir('src/veritysetup')
subdir('src/vmspawn')
subdir('src/volatile-root')
subdir('src/vpick')
subdir('src/xdg-autostart-generator')

subdir('src/systemd')

subdir('src/test')
subdir('src/fuzz')
subdir('src/ukify/test')  # needs to be last for test_env variable
subdir('test/fuzz')

subdir('mime')

alias_target('devel', libsystemd_pc, libudev_pc, systemd_pc, udev_pc)

#####################################################################

foreach test : simple_tests
        executables += test_template + { 'sources' : [test] }
endforeach

foreach test : libsystemd_tests
        executables += test_template + test
endforeach

foreach fuzzer : simple_fuzzers
        executables += fuzz_template + { 'sources' : [fuzzer] }
endforeach

foreach dict : executables
        name = dict.get('name', '')
        if name == ''
                name = fs.stem(dict.get('sources')[0])
                assert(name.split('-')[0] in ['test', 'fuzz'])
        endif

        is_test = name.startswith('test-')
        is_fuzz = name.startswith('fuzz-')
        is_standalone = name.endswith('.standalone')

        build = true
        foreach cond : dict.get('conditions', [])
                if conf.get(cond) != 1
                        build = false
                        break
                endif
        endforeach
        if not build
                continue
        endif

        exe_sources = dict.get('sources', []) + dict.get('extract', [])

        kwargs = {}
        foreach key, val : dict
                if key in ['name', 'dbus', 'public', 'conditions', 'type', 'suite',
                           'timeout', 'parallel', 'objects', 'sources', 'extract',
                           'include_directories', 'build_by_default', 'install']
                        continue
                endif

                kwargs += { key : val }
        endforeach

        foreach key, val : executable_additional_kwargs
                kwargs += { key : [ kwargs.get(key, []), val ]}
        endforeach

        include_directories = dict['include_directories']
        if not is_test and exe_sources.length() > 0
                include_directories += fs.parent(exe_sources[0])
        endif

        foreach val : dict.get('objects', [])
                obj = objects_by_name[val]
                kwargs += { 'objects' : obj['objects'] }
                include_directories += obj['include_directories']
        endforeach

        if is_test
                kwargs += { 'install_dir' : kwargs.get('install_dir') / dict.get('type', '') }
                foreach key, val : test_additional_kwargs
                        kwargs += { key : [ kwargs.get(key, []), val ] }
                endforeach
        endif

        if is_fuzz
                include_directories += include_directories('src/fuzz')
                foreach key, val : fuzz_additional_kwargs
                        if key == 'sources'
                                exe_sources += val
                        else
                                kwargs += { key : [ kwargs.get(key, []), val ] }
                        endif
                endforeach
        endif

        build_by_default = dict.get('build_by_default',
                                    have_standalone_binaries or not is_standalone)

        if not is_standalone
                install = dict.get('install', true)
        else
                install = have_standalone_binaries
        endif

        exe = executable(
                name,
                sources : exe_sources,
                kwargs : kwargs,
                implicit_include_directories : false,
                include_directories : include_directories,
                build_by_default: build_by_default,
                install: install,
        )

        executables_by_name += { name : exe }

        if not is_standalone
                sources += exe_sources
        endif

        if dict.has_key('extract')
                objects_by_name += {
                        name : {
                                'objects' : exe.extract_objects(dict['extract']),
                                'include_directories' : fs.parent(dict['extract'][0]),
                        }
                }
        endif

        if build_by_default
                if dict.get('dbus', false)
                        dbus_programs += exe
                endif
                if dict.get('public', false)
                        public_programs += exe
                endif
        endif

        if is_test
                type = dict.get('type', '')
                suite = dict.get('suite', '')
                if suite == ''
                        suite = fs.name(fs.parent(dict.get('sources')[0]))
                        if suite.startswith('sd-')
                                suite = 'libsystemd'
                        endif
                endif

                if type == 'manual'
                        message(f'@suite@/@name@ is a manual test')
                elif type == 'unsafe' and want_tests != 'unsafe'
                        message(f'@suite@/@name@ is an unsafe test')
                elif dict.get('build_by_default')
                        test(name, exe,
                             env : test_env,
                             timeout : dict.get('timeout', 30),
                             suite : suite,
                             is_parallel : dict.get('parallel', true))
                endif
        endif

        if is_fuzz
                fuzzer_exes += exe

                if want_tests != 'false' and want_fuzz_tests
                        fuzz_ins = fuzz_regression_tests.get(name, {})
                        foreach directive : fuzz_ins.get('directives', [])
                                tt = '@0@_@1@'.format(name, fs.name(directive.full_path()))
                                if tt.substring(45) != ''
                                        error('Directive sample name is too long:', directive.full_path())
                                endif

                                test(tt,
                                     exe,
                                     suite : 'fuzz',
                                     args : directive.full_path(),
                                     env : ['UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1'],
                                     timeout : 60,
                                     depends : directive)
                        endforeach
                        foreach file : fuzz_ins.get('files', [])
                                tt = '@0@_@1@'.format(name, fs.name(file))
                                if tt.substring(45) != ''
                                        error('Fuzz sample name is too long:', fs.name(file))
                                endif

                                test(tt,
                                     exe,
                                     suite : 'fuzz',
                                     env : ['UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1'],
                                     timeout : 60,
                                     args : file)
                        endforeach
                endif
        endif
endforeach

alias_target('fuzzers', fuzzer_exes)

#####################################################################

test_dlopen = executables_by_name.get('test-dlopen')

nss_targets = []
pam_targets = []
foreach dict : modules
        name = dict.get('name')
        is_nss = name.startswith('nss_')
        is_pam = name.startswith('pam_')

        build = true
        foreach cond : dict.get('conditions', [])
                if conf.get(cond) != 1
                        build = false
                        break
                endif
        endforeach
        if not build
                continue
        endif

        kwargs = {}
        foreach key, val : dict
                if key in ['name', 'conditions', 'version-script']
                        continue
                endif
                kwargs += { key : val }
        endforeach

        kwargs += {
                'link_args' : [
                        kwargs.get('link_args', []),
                        '-Wl,--version-script=' + dict.get('version-script'),
                ],
                'link_depends' : [
                        kwargs.get('link_depends', []),
                        dict.get('version-script'),
                ],
        }
        foreach key, val : module_additional_kwargs
                kwargs += { key : [ kwargs.get(key, []), val ]}
        endforeach

        lib = shared_library(
                name,
                kwargs : kwargs,
                implicit_include_directories : false,
        )

        if is_nss
                # We cannot use shared_module because it does not support version suffix.
                # Unfortunately shared_library insists on creating the symlink…
                meson.add_install_script(sh, '-c', f'rm -f $DESTDIR@libdir@/lib@name@.so',
                                         install_tag : 'nss')
                nss_targets += lib
        endif

        if is_pam
                pam_targets += lib
        endif

        if want_tests != 'false' and (is_nss or is_pam)
                test('dlopen-' + name,
                     test_dlopen,
                     # path to dlopen must include a slash
                     args : lib.full_path(),
                     depends : lib,
                     suite : is_nss ? 'nss' : 'pam')
        endif
endforeach

# We need the actual targets to build aliases
if nss_targets.length() > 0
        alias_target('nss', nss_targets)
endif
if pam_targets.length() > 0
        alias_target('pam', pam_targets)
endif

#####################################################################

ukify_depends = []

foreach executable : ['systemd-measure', 'systemd-sbsign', 'systemd-keyutil']
        if executable in executables_by_name
                ukify_depends += [executables_by_name[executable]]
        endif
endforeach

ukify = custom_target(
        input : 'src/ukify/ukify.py',
        output : 'ukify',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : want_ukify,
        install_mode : 'rwxr-xr-x',
        depends : ukify_depends,
        install_dir : bindir)
if want_ukify
        public_programs += ukify

        # symlink for backwards compatibility after rename
        install_symlink('ukify',
                        pointing_to : libexecdir_to_bin / 'ukify',
                        install_dir : libexecdir)
endif

#####################################################################

mkosi = find_program('mkosi', required : false)
mkosi_depends = public_programs

foreach executable : ['systemd-journal-remote', 'systemd-sbsign', 'systemd-keyutil']
        if executable in executables_by_name
                mkosi_depends += [executables_by_name[executable]]
        endif
endforeach

if mkosi.found()
        custom_target(
                build_always_stale : true,
                build_by_default: false,
                console : true,
                output : 'mkosi',
                command : [
                        mkosi,
                        '--directory', meson.current_source_dir(),
                        '--output-dir', meson.current_build_dir() / 'mkosi.output',
                        '--cache-dir', meson.current_build_dir() / 'mkosi.cache',
                        '--build-dir', meson.current_build_dir() / 'mkosi.builddir',
                        '--extra-search-path', meson.current_build_dir(),
                        '--force',
                        'build',
                ],
                depends : mkosi_depends,
        )
endif

if install_tests
        install_subdir('mkosi',
                       install_dir : testsdir,
                       exclude_files : ['mkosi.local.conf', 'mkosi.key', 'mkosi.crt'],
                       exclude_directories : ['mkosi.local'])
endif

############################################################

subdir('rules.d')
subdir('test')

#####################################################################

subdir('docs/var-log')
subdir('hwdb.d')
subdir('man')
subdir('modprobe.d')
subdir('network')
subdir('presets')
subdir('profile.d')
subdir('shell-completion/bash')
subdir('shell-completion/zsh')
subdir('sysctl.d')
subdir('sysusers.d')
subdir('tmpfiles.d')
subdir('units')

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
             'docs/ENVIRONMENT.md',
             'docs/TRANSIENT-SETTINGS.md',
             'docs/UIDS-GIDS.md',
             install_dir : docdir)

install_subdir('LICENSES',
               install_dir : docdir)

#####################################################################

# Ensure that changes to the docs/ directory do not break the
# basic Github pages build. But only run it in developer mode,
# as it might be fragile due to changes in the tooling, and it is
# not generally useful for users.
jekyll = find_program('jekyll', required : false)
if get_option('mode') == 'developer' and want_tests != 'false' and jekyll.found()
        test('github-pages',
             jekyll,
             suite : 'dist',
             args : ['build',
                     '--source', meson.project_source_root() / 'docs',
                     '--destination', meson.project_build_root() / '_site'])
endif

#####################################################################

foreach exec : public_programs
        name = fs.name(exec.full_path())
        if want_tests != 'false'
                test('check-help-' + name,
                     check_help_sh,
                     suite : 'dist',
                     args : exec.full_path(),
                     depends: exec)

                test('check-version-' + name,
                     check_version_sh,
                     suite : 'dist',
                     args : [exec.full_path(),
                             project_major_version],
                     depends: exec)
        endif
endforeach

#####################################################################

if git.found()
        all_files = run_command(
                env, '-u', 'GIT_WORK_TREE',
                git, '--git-dir=@0@/.git'.format(meson.project_source_root()),
                     'ls-files', ':/*.[ch]', ':/*.cc',
                check : false)
        if all_files.returncode() == 0
                all_files = files(all_files.stdout().split())

                custom_target(
                        output : 'tags',
                        command : [env, 'etags', '-o', '@0@/TAGS'.format(meson.project_source_root())] + all_files)
                run_target(
                        'ctags',
                        command : [env, 'ctags', '--tag-relative=never', '-o', '@0@/tags'.format(meson.project_source_root())] + all_files)
        endif

        ####################################################

        run_target(
                'git-contrib',
                command : git_contrib_sh)

        ####################################################

        git_head = run_command(
                git, '--git-dir=@0@/.git'.format(meson.project_source_root()),
                     'rev-parse', 'HEAD',
                check : false).stdout().strip()
        git_head_short = run_command(
                git, '--git-dir=@0@/.git'.format(meson.project_source_root()),
                     'rev-parse', '--short=7', 'HEAD',
                check : false).stdout().strip()

        run_target(
                'git-snapshot',
                command : [git, 'archive',
                           '-o', '@0@/systemd-@1@.tar.gz'.format(meson.project_source_root(),
                                                                 git_head_short),
                           '--prefix', f'systemd-@git_head@/',
                           'HEAD'])
endif

#####################################################################

alias_target('gensources', generated_sources)

clang_tidy = find_program('clang-tidy', required : false)
if meson.version().version_compare('>=1.4.0')
        uniq = {}

        foreach source : sources
                if uniq.has_key(source.full_path())
                        continue
                endif
                uniq += {source.full_path(): source}
        endforeach

        # TODO: Use uniq.values() when we can rely on meson 1.10.0.
        sources = []
        foreach path, file : uniq
                sources += [file]
        endforeach

        foreach source : sources
                if systemd_headers.contains(source)
                        continue
                endif

                if not source.full_path().endswith('.c') and not source.full_path().endswith('.h')
                        continue
                endif

                inputs = [source]

                header = source.full_path().replace('.c', '.h')
                if fs.exists(header) and header != source.full_path() and header != libudev_h_path
                        inputs += header
                endif

                foreach input : inputs
                        if clang_tidy.found()
                                test(
                                        'clang-tidy-@0@'.format(fs.name(input)),
                                        clang_tidy,
                                        args : ['-p', meson.project_build_root(), input],
                                        suite : 'clang-tidy',
                                        depends : generated_sources,
                                )
                        endif
                endforeach
        endforeach
endif

symbol_analysis_exes = []
foreach name, exe : executables_by_name
        symbol_analysis_exes += exe
endforeach

test(
        'libshared-unused-symbols',
        find_unused_library_symbols_py,
        suite : 'unused-symbols',
        args : [libshared, libcore] + nss_targets + pam_targets + symbol_analysis_exes,
)

run_target(
        'check-api-docs',
        depends : [man, libsystemd, libudev],
        command : [check_api_docs_sh,
                   libsystemd.full_path(),
                   libudev.full_path()])

alias_target('man', man)
alias_target('html', html)
alias_target('update-dbus-docs', update_dbus_docs)
alias_target('update-man-rules', update_man_rules)

if not meson.is_cross_build()
        custom_target(
                'export-dbus-interfaces',
                output : fs.name(dbus_interfaces_dir),
                install : dbus_interfaces_dir != 'no',
                install_dir : fs.parent(dbus_interfaces_dir),
                command : [dbus_exporter_py, '@OUTPUT@', dbus_programs])
endif

custom_target(
        output : 'installed-unit-files.txt',
        capture : true,
        install : want_tests != 'no' and install_tests,
        install_dir : testdata_dir,
        command : [meson_extract_unit_files_py,
                   meson.project_build_root()])

#####################################################################

udev_targets = []
foreach bin : udev_binaries
        udev_targets += executables_by_name.get(bin, [])
endforeach
alias_target('udev', buildable_rules, udev_targets, udev_units)

if conf.get('ENABLE_HWDB') == 1
        alias_target('hwdb', auto_suspend_rules, executables_by_name.get('systemd-hwdb'), hwdb_units)
endif

alt_time_epoch = run_command('date', '-Is', '-u', '-d', f'@@time_epoch@', check : false)
if alt_time_epoch.returncode() != 0
        # If the above fails, maybe the date(1) uses BSD-style syntax
        alt_time_epoch = run_command('date', '-Iseconds', '-u', '-r', f'@time_epoch@', check : true)
endif
alt_time_epoch = alt_time_epoch.stdout().strip()

summary({
        'split bin-sbin'                            : split_bin,
        'prefix directory'                          : prefixdir,
        'sysconf directory'                         : sysconfdir,
        'include directory'                         : includedir,
        'lib directory'                             : libdir,
        'PAM modules directory'                     : pamlibdir,
        'PAM configuration directory'               : pamconfdir,
        'ssh server configuration directory'        : sshdconfdir,
        'ssh server privilege separation directory' : sshdprivsepdir,
        'ssh client configuration directory'        : sshconfdir,
        'libcryptsetup plugins directory'           : libcryptsetup_plugins_dir,
        'Shell profile directory'                   : shellprofiledir,
        'RPM macros directory'                      : rpmmacrosdir,
        'modprobe.d directory'                      : modprobedir,
        'D-Bus policy directory'                    : dbuspolicydir,
        'D-Bus session directory'                   : dbussessionservicedir,
        'D-Bus system directory'                    : dbussystemservicedir,
        'D-Bus interfaces directory'                : dbus_interfaces_dir,
        'bash completions directory'                : bashcompletiondir,
        'zsh completions directory'                 : zshcompletiondir,
        'private shared lib version tag'            : shared_lib_tag,
        'debug shell'                               : '@0@ @ @1@'.format(get_option('debug-shell'),
                                                                         get_option('debug-tty')),
        'system UIDs'                               : '<=@0@ (alloc >=@1@)'.format(conf.get('SYSTEM_UID_MAX'),
                                                      conf.get('SYSTEM_ALLOC_UID_MIN')),
        'system GIDs'                               : '<=@0@ (alloc >=@1@)'.format(conf.get('SYSTEM_GID_MAX'),
                                                      conf.get('SYSTEM_ALLOC_GID_MIN')),
        'greeter UIDs'                              : f'@greeter_uid_min@…@greeter_uid_max@',
        'dynamic UIDs'                              : f'@dynamic_uid_min@…@dynamic_uid_max@',
        'container UID bases'                       : f'@container_uid_base_min@…@container_uid_base_max@',
        'foreign UID base'                          : f'@foreign_uid_base@',
        'static UID/GID allocations'                : ' '.join(static_ugids),
        '/dev/kvm access mode'                      : get_option('dev-kvm-mode'),
        'render group access mode'                  : get_option('group-render-mode'),
        'certificate root directory'                : get_option('certificate-root'),
        'support URL'                               : support_url,
        'nobody user name'                          : nobody_user,
        'nobody group name'                         : nobody_group,
        'fallback hostname'                         : get_option('fallback-hostname'),
        'default compression method'                : compression,
        'default DNSSEC mode'                       : default_dnssec,
        'default DNS-over-TLS mode'                 : default_dns_over_tls,
        'default mDNS mode'                         : default_mdns,
        'default LLMNR mode'                        : default_llmnr,
        'default DNS servers'                       : dns_servers.split(' '),
        'default NTP servers'                       : ntp_servers.split(' '),
        'default net.naming_scheme= value'          : default_net_naming_scheme,
        'default KillUserProcesses= value'          : kill_user_processes,
        'default locale'                            : default_locale,
        'default nspawn locale'                     : nspawn_locale,
        'default status unit format'                : status_unit_format_default,
        'default journal storage mode'              : conf.get('JOURNAL_STORAGE_DEFAULT'),
        'default user $PATH'                        : default_user_path != '' ? default_user_path : '(same as system services)',
        'systemd service watchdog'                  : service_watchdog == '' ? 'disabled' : service_watchdog,
        'time epoch'                                : f'@time_epoch@ (@alt_time_epoch@)',
        'TPM2 nvpcr base'                           : run_command(sh, '-c', 'printf 0x%x @0@'.format(get_option('tpm2-nvpcr-base')), check : true).stdout()
})

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
        ['IPE'],
        ['PAM'],
        ['SECCOMP'],
        ['SELinux'],
        ['SMACK'],
        ['blkid'],
        ['elfutils'],
        ['gcrypt'],
        ['gnutls'],
        ['libarchive'],
        ['libbpf'],
        ['libcrypt'],
        ['libcryptsetup'],
        ['libcryptsetup-plugins'],
        ['libcurl'],
        ['libfdisk'],
        ['libfido2'],
        ['libidn2'],
        ['microhttpd'],
        ['openssl'],
        ['p11kit'],
        ['passwdqc'],
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
        ['bootloader'],
        ['bpf-framework',          conf.get('BPF_FRAMEWORK') == 1],
        ['coredump'],
        ['efi'],
        ['environment.d'],
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
        ['mountfsd'],
        ['networkd'],
        ['nspawn'],
        ['nsresourced'],
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
        ['sysupdated'],
        ['sysusers'],
        ['storagetm'],
        ['timedated'],
        ['timesyncd'],
        ['tmpfiles'],
        ['userdb'],
        ['vconsole'],
        ['vmspawn'],
        ['xdg-autostart'],

        # optional features
        ['dmi'],
        ['DNS-over-TLS'],
        ['idn'],
        ['polkit'],
        ['legacy-pkla',            install_polkit_pkla],
        ['kmod'],
        ['xenctrl'],
        ['dbus'],
        ['glib'],
        ['tpm'],
        ['man pages',              want_man],
        ['html pages',             want_html],
        ['man page indices',       want_man and have_lxml],
        ['compat-mutable-uid-boundaries'],
        ['compat-sysv-interfaces'],
        ['utmp'],
        ['ldconfig'],
        ['adm group',              get_option('adm-group')],
        ['wheel group',            get_option('wheel-group')],
        ['gshadow'],
        ['debug hashmap'],
        ['debug mmap cache'],
        ['debug siphash'],
        ['trace logging',          conf.get('LOG_TRACE') == 1],
        ['slow tests',             want_slow_tests],
        ['fuzz tests',             want_fuzz_tests],
        ['install tests',          install_tests],
        ['link-udev-shared',       get_option('link-udev-shared')],
        ['link-systemctl-shared',  get_option('link-systemctl-shared')],
        ['link-networkd-shared',   get_option('link-networkd-shared')],
        ['link-timesyncd-shared',  get_option('link-timesyncd-shared')],
        ['link-journalctl-shared', get_option('link-journalctl-shared')],
        ['link-boot-shared',       get_option('link-boot-shared')],
        ['link-portabled-shared',  get_option('link-portabled-shared')],
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
        found += f'static-libsystemd(@static_libsystemd@)'
endif

if static_libudev == 'false'
        missing += 'static-libudev'
else
        found += f'static-libudev(@static_libudev@)'
endif

summary({
                'enabled'  : ', '.join(found),
                'disabled' : ', '.join(missing)
        },
        section : 'Features')

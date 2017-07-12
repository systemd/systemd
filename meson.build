project('systemd', 'c',
        version : '234',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu99',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
        ],
        meson_version : '>= 0.40',
       )

# We need the same data in three different formats, ugh!
# Also, for hysterical reasons, we use different variable
# names, sometimes. Not all variables are included in every
# set. Ugh, ugh, ugh!
conf = configuration_data()
conf.set_quoted('PACKAGE_STRING',  meson.project_name() + ' ' + meson.project_version())
conf.set_quoted('PACKAGE_VERSION', meson.project_version())

substs = configuration_data()
substs.set('PACKAGE_URL',          'https://www.freedesktop.org/wiki/Software/systemd')
substs.set('PACKAGE_VERSION',      meson.project_version())

m4_defines = []

#####################################################################

rootprefixdir = get_option('rootprefix')
if get_option('split-usr')
        conf.set('HAVE_SPLIT_USR', true)
        rootprefixdir = rootprefixdir != '' ? rootprefixdir : '/'
else
        rootprefixdir = rootprefixdir != '' ? rootprefixdir : '/usr'
endif

sysvinit_path = get_option('sysvinit-path')
sysvrcnd_path = get_option('sysvrcnd-path')
if sysvinit_path != '' or sysvrcnd_path != ''
        conf.set('HAVE_SYSV_COMPAT', true,
                 description : 'SysV init scripts and rcN.d links are supported')
        m4_defines += ['-DHAVE_SYSV_COMPAT']
endif

# join_paths ignore the preceding arguments if an absolute component is
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
rootlibexecdir = join_paths(rootprefixdir, 'lib/systemd')

rootlibdir = get_option('rootlibdir')
if rootlibdir == ''
        rootlibdir = join_paths(rootprefixdir, libdir.split('/')[-1])
endif

# Dirs of external packages
pkgconfigdatadir = join_paths(datadir, 'pkgconfig')
pkgconfiglibdir = join_paths(libdir, 'pkgconfig')
polkitpolicydir = join_paths(datadir, 'polkit-1/actions')
polkitrulesdir = join_paths(datadir, 'polkit-1/rules.d')
polkitpkladir = join_paths(localstatedir, 'lib/polkit-1/localauthority/10-vendor.d')
varlogdir = join_paths(localstatedir, 'log')
xinitrcdir = join_paths(sysconfdir, 'X11/xinit/xinitrc.d')
rpmmacrosdir = get_option('rpmmacrosdir')

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
udevhomedir = udevlibexecdir
udevrulesdir = join_paths(udevlibexecdir, 'rules.d')
udevhwdbdir = join_paths(udevlibexecdir, 'hwdb.d')
catalogdir = join_paths(prefixdir, 'lib/systemd/catalog')
kernelinstalldir = join_paths(prefixdir, 'lib/kernel/install.d')
factorydir = join_paths(datadir, 'factory')
docdir = join_paths(datadir, 'doc/systemd')
bootlibdir = join_paths(prefixdir, 'lib/systemd/boot/efi')
testsdir = join_paths(prefixdir, 'lib/systemd/tests')
systemdstatedir = join_paths(localstatedir, 'lib/systemd')
catalogstatedir = join_paths(systemdstatedir, 'catalog')
randomseeddir = join_paths(localstatedir, 'lib/systemd')

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

conf.set_quoted('PKGSYSCONFDIR',                              pkgsysconfdir)
conf.set_quoted('SYSTEM_CONFIG_UNIT_PATH',                    join_paths(pkgsysconfdir, 'system'))
conf.set_quoted('SYSTEM_DATA_UNIT_PATH',                      systemunitdir)
conf.set_quoted('SYSTEM_SYSVINIT_PATH',                       sysvinit_path)
conf.set_quoted('SYSTEM_SYSVRCND_PATH',                       sysvrcnd_path)
conf.set_quoted('RC_LOCAL_SCRIPT_PATH_START',                 get_option('rc-local'))
conf.set_quoted('RC_LOCAL_SCRIPT_PATH_STOP',                  get_option('halt-local'))
conf.set_quoted('USER_CONFIG_UNIT_PATH',                      join_paths(pkgsysconfdir, 'user'))
conf.set_quoted('USER_DATA_UNIT_PATH',                        userunitdir)
conf.set_quoted('CERTIFICATE_ROOT',                           get_option('certificate-root'))
conf.set_quoted('CATALOG_DATABASE',                           join_paths(catalogstatedir, 'database'))
conf.set_quoted('SYSTEMD_CGROUP_AGENT_PATH',                  join_paths(rootlibexecdir, 'systemd-cgroups-agent'))
conf.set_quoted('SYSTEMD_BINARY_PATH',                        join_paths(rootlibexecdir, 'systemd'))
conf.set_quoted('SYSTEMD_FSCK_PATH',                          join_paths(rootlibexecdir, 'systemd-fsck'))
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
conf.set_quoted('UDEVLIBEXECDIR',                             udevlibexecdir)
conf.set_quoted('POLKIT_AGENT_BINARY_PATH',                   join_paths(bindir, 'pkttyagent'))
conf.set_quoted('LIBDIR',                                     libdir)
conf.set_quoted('ROOTLIBDIR',                                 rootlibdir)
conf.set_quoted('ROOTLIBEXECDIR',                             rootlibexecdir)
conf.set_quoted('BOOTLIBDIR',                                 bootlibdir)
conf.set_quoted('SYSTEMD_PULL_PATH',                          join_paths(rootlibexecdir, 'systemd-pull'))
conf.set_quoted('SYSTEMD_IMPORT_PATH',                        join_paths(rootlibexecdir, 'systemd-import'))
conf.set_quoted('SYSTEMD_EXPORT_PATH',                        join_paths(rootlibexecdir, 'systemd-export'))
conf.set_quoted('VENDOR_KEYRING_PATH',                        join_paths(rootlibexecdir, 'import-pubring.gpg'))
conf.set_quoted('USER_KEYRING_PATH',                          join_paths(pkgsysconfdir, 'import-pubring.gpg'))
conf.set_quoted('DOCUMENT_ROOT',                              join_paths(pkgdatadir, 'gatewayd'))

conf.set_quoted('ABS_BUILD_DIR',                              meson.build_root())
conf.set_quoted('ABS_SRC_DIR',                                meson.source_root())

substs.set('prefix',                                          prefixdir)
substs.set('exec_prefix',                                     prefixdir)
substs.set('libdir',                                          libdir)
substs.set('rootlibdir',                                      rootlibdir)
substs.set('includedir',                                      includedir)
substs.set('pkgsysconfdir',                                   pkgsysconfdir)
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
substs.set('catalogdir',                                      catalogdir)
substs.set('tmpfilesdir',                                     tmpfilesdir)
substs.set('sysusersdir',                                     sysusersdir)
substs.set('sysctldir',                                       sysctldir)
substs.set('binfmtdir',                                       binfmtdir)
substs.set('modulesloaddir',                                  modulesloaddir)
substs.set('systemgeneratordir',                              systemgeneratordir)
substs.set('usergeneratordir',                                usergeneratordir)
substs.set('systemenvgeneratordir',                           systemenvgeneratordir)
substs.set('userenvgeneratordir',                             userenvgeneratordir)
substs.set('systemshutdowndir',                               systemshutdowndir)
substs.set('systemsleepdir',                                  systemsleepdir)
substs.set('VARLOGDIR',                                       varlogdir)
substs.set('CERTIFICATEROOT',                                 get_option('certificate-root'))
substs.set('SYSTEMCTL',                                       join_paths(rootbindir, 'systemctl'))
substs.set('RANDOM_SEED',                                     join_paths(randomseeddir, 'random-seed'))
substs.set('SYSTEM_SYSVINIT_PATH',                            sysvinit_path)
substs.set('SYSTEM_SYSVRCND_PATH',                            sysvrcnd_path)
substs.set('RC_LOCAL_SCRIPT_PATH_START',                      get_option('rc-local'))
substs.set('RC_LOCAL_SCRIPT_PATH_STOP',                       get_option('halt-local'))

#####################################################################

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')
check_compilation_sh = find_program('tools/meson-check-compilation.sh')

cxx = find_program('c++', required : false)
if cxx.found()
        #  Used only for tests
        add_languages('cpp')
endif

foreach arg : ['-Wextra',
               '-Wundef',
               '-Wlogical-op',
               '-Wmissing-include-dirs',
               '-Wold-style-definition',
               '-Wpointer-arith',
               '-Winit-self',
               '-Wdeclaration-after-statement',
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
               '-Wshadow',
               '-Wendif-labels',
               '-Wstrict-aliasing=2',
               '-Wwrite-strings',
               '-Werror=overflow',
               '-Wdate-time',
               '-Wnested-externs',
               '-ffast-math',
               '-fno-common',
               '-fdiagnostics-show-option',
               '-fno-strict-aliasing',
               '-fvisibility=hidden',
               '-fstack-protector',
               '-fstack-protector-strong',
               '-fPIE',
               '--param=ssp-buffer-size=4',
              ]
        if cc.has_argument(arg)
                add_project_arguments(arg, language : 'c')
        endif
endforeach

# "negative" arguments: gcc on purpose does not return an error for "-Wno-"
# arguments, just emits a warnings. So test for the "positive" version instead.
foreach arg : ['unused-parameter',
               'missing-field-initializers',
               'unused-result',
               'format-signedness']
        if cc.has_argument('-W' + arg)
                add_project_arguments('-Wno-' + arg, language : 'c')
        endif
endforeach

if cc.compiles('
   #include <time.h>
   #include <inttypes.h>
   typedef uint64_t usec_t;
   usec_t now(clockid_t clock);
   int main(void) {
           struct timespec now;
           return 0;
   }
', name : '-Werror=shadow with local shadowing')
        add_project_arguments('-Werror=shadow', language : 'c')
endif

if cc.get_id() == 'clang'
        foreach arg : ['-Wno-typedef-redefinition',
                       '-Wno-gnu-variable-sized-type-not-at-end',
                      ]
                if cc.has_argument(arg,
                                   name : '@0@ is supported'.format(arg))
                        add_project_arguments(arg, language : 'c')
                endif
        endforeach
endif

link_test_c = files('tools/meson-link-test.c')

# --as-needed and --no-undefined are provided by meson by default,
# run mesonconf to see what is enabled
foreach arg : ['-Wl,-z,relro',
               '-Wl,-z,now',
               '-pie',
              ]

        have = run_command(check_compilation_sh,
                           cc.cmd_array(), '-x', 'c', arg,
                           '-include', link_test_c).returncode() == 0
        message('Linking with @0@ supported: @1@'.format(arg, have ? 'yes' : 'no'))
        if have
                add_project_link_arguments(arg, language : 'c')
        endif
endforeach

if get_option('buildtype') != 'debug'
        foreach arg : ['-ffunction-sections',
                       '-fdata-sections']
                if cc.has_argument(arg,
                                   name : '@0@ is supported'.format(arg))
                        add_project_arguments(arg, language : 'c')
                endif
        endforeach

        foreach arg : ['-Wl,--gc-sections']
                have = run_command(check_compilation_sh,
                                   cc.cmd_array(), '-x', 'c', arg,
                                   '-include', link_test_c).returncode() == 0
                message('Linking with @0@ supported: @1@'.format(arg, have ? 'yes' : 'no'))
                if have
                        add_project_link_arguments(arg, language : 'c')
                endif
        endforeach
endif

cpp = ' '.join(cc.cmd_array()) + ' -E'

#####################################################################
# compilation result tests

conf.set('_GNU_SOURCE', true)
conf.set('__SANE_USERSPACE_TYPES__', true)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_INO_T', cc.sizeof('ino_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))
conf.set('SIZEOF_RLIM_T', cc.sizeof('rlim_t', prefix : '#include <sys/resource.h>'))

decl_headers = '''
#include <uchar.h>
#include <linux/ethtool.h>
'''
# FIXME: key_serial_t is only defined in keyutils.h, this is bound to fail

foreach decl : ['char16_t',
                'char32_t',
                'key_serial_t',
                'struct ethtool_link_settings',
               ]

        # We get -1 if the size cannot be determined
        have = cc.sizeof(decl, prefix : decl_headers) > 0
        conf.set('HAVE_' + decl.underscorify().to_upper(), have)
endforeach

foreach decl : [['IFLA_INET6_ADDR_GEN_MODE',         'linux/if_link.h'],
                ['IN6_ADDR_GEN_MODE_STABLE_PRIVACY', 'linux/if_link.h'],
                ['IFLA_VRF_TABLE',                   'linux/if_link.h'],
                ['IFLA_MACVLAN_FLAGS',               'linux/if_link.h'],
                ['IFLA_IPVLAN_MODE',                 'linux/if_link.h'],
                ['IFLA_PHYS_PORT_ID',                'linux/if_link.h'],
                ['IFLA_BOND_AD_INFO',                'linux/if_link.h'],
                ['IFLA_VLAN_PROTOCOL',               'linux/if_link.h'],
                ['IFLA_VXLAN_REMCSUM_NOPARTIAL',     'linux/if_link.h'],
                ['IFLA_VXLAN_GPE',                   'linux/if_link.h'],
                ['IFLA_GENEVE_LABEL',                'linux/if_link.h'],
                # if_tunnel.h is buggy and cannot be included on its own
                ['IFLA_VTI_REMOTE',                  'linux/if_tunnel.h', '#include <net/if.h>'],
                ['IFLA_IPTUN_ENCAP_DPORT',           'linux/if_tunnel.h', '#include <net/if.h>'],
                ['IFLA_GRE_ENCAP_DPORT',             'linux/if_tunnel.h', '#include <net/if.h>'],
                ['IFLA_BRIDGE_VLAN_INFO',            'linux/if_bridge.h'],
                ['IFLA_BRPORT_PROXYARP',             'linux/if_link.h'],
                ['IFLA_BRPORT_LEARNING_SYNC',        'linux/if_link.h'],
                ['IFLA_BR_VLAN_DEFAULT_PVID',        'linux/if_link.h'],
                ['NDA_IFINDEX',                      'linux/neighbour.h'],
                ['IFA_FLAGS',                        'linux/if_addr.h'],
                ['LO_FLAGS_PARTSCAN',                'linux/loop.h'],
               ]
        prefix = decl.length() > 2 ? decl[2] : ''
        have = cc.has_header_symbol(decl[1], decl[0], prefix : prefix)
        conf.set10('HAVE_DECL_' + decl[0], have)
endforeach

skip = false
foreach ident : ['secure_getenv', '__secure_getenv']
        if not skip and cc.has_function(ident)
                conf.set('HAVE_' + ident.to_upper(), true)
                skip = true
        endif
endforeach

foreach ident : [
        ['memfd_create',      '''#include <sys/memfd.h>'''],
        ['gettid',            '''#include <sys/types.h>'''],
        ['pivot_root',        '''#include <stdlib.h>'''],     # no known header declares pivot_root
        ['name_to_handle_at', '''#define _GNU_SOURCE
                                 #include <sys/types.h>
                                 #include <sys/stat.h>
                                 #include <fcntl.h>'''],
        ['setns',             '''#define _GNU_SOURCE
                                 #include <sched.h>'''],
        ['renameat2',         '''#include <stdio.h>'''],
        ['kcmp',              '''#include <linux/kcmp.h>'''],
        ['keyctl',            '''#include <sys/types.h>
                                 #include <keyutils.h>'''],
        ['copy_file_range',   '''#include <sys/syscall.h>
                                 #include <unistd.h>'''],
        ['explicit_bzero' ,   '''#include <string.h>'''],
]

        have = cc.has_function(ident[0], prefix : ident[1])
        conf.set10('HAVE_DECL_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''')
        conf.set('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_DECL_GETRANDOM', true)
else
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('HAVE_DECL_GETRANDOM', have)
endif

#####################################################################

sed = find_program('sed')
grep = find_program('grep')
awk = find_program('awk')
m4 = find_program('m4')
stat = find_program('stat')
git = find_program('git', required : false)

meson_make_symlink = meson.source_root() + '/tools/meson-make-symlink.sh'
mkdir_p = 'mkdir -p $DESTDIR/@0@'
test_efi_create_disk_sh = find_program('test/test-efi-create-disk.sh')
splash_bmp = files('test/splash.bmp')

# if -Dxxx-path option is found, use that. Otherwise, check in $PATH,
# /usr/sbin, /sbin, and fall back to the default from middle column.
progs = [['telinit',    '/lib/sysvinit/telinit'],
         ['quotaon',    '/usr/sbin/quotaon'    ],
         ['quotacheck', '/usr/sbin/quotacheck' ],
         ['kill',       '/usr/bin/kill'        ],
         ['kmod',       '/usr/bin/kmod'        ],
         ['kexec',      '/usr/sbin/kexec'      ],
         ['sulogin',    '/usr/sbin/sulogin'    ],
         ['mount',      '/usr/bin/mount',      'MOUNT_PATH'],
         ['umount',     '/usr/bin/umount',     'UMOUNT_PATH'],
         ['loadkeys',   '/usr/bin/loadkeys',   'KBD_LOADKEYS'],
         ['setfont',    '/usr/bin/setfont',    'KBD_SETFONT'],
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

if run_command('ln', '--relative', '--help').returncode() != 0
        error('ln does not support --relative')
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
foreach header : ['linux/btrfs.h',
                  'linux/memfd.h',
                  'linux/vm_sockets.h',
                  'valgrind/memcheck.h',
                  'valgrind/valgrind.h',
                 ]

        conf.set('HAVE_' + header.underscorify().to_upper(),
                 cc.has_header(header))
endforeach

############################################################

conf.set_quoted('FALLBACK_HOSTNAME', get_option('fallback-hostname'))

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

time_epoch = get_option('time-epoch')
if time_epoch == ''
        NEWS = files('NEWS')
        time_epoch = run_command(stat, '-c', '%Y', NEWS).stdout()
endif
time_epoch = time_epoch.to_int()
conf.set('TIME_EPOCH', time_epoch)

system_uid_max = get_option('system-uid-max')
if system_uid_max == ''
        system_uid_max = run_command(
                awk,
                'BEGIN { uid=999 } /^\s*SYS_UID_MAX\s+/ { uid=$2 } END { print uid }',
                '/etc/login.defs').stdout()
endif
system_uid_max = system_uid_max.to_int()
conf.set('SYSTEM_UID_MAX', system_uid_max)
substs.set('systemuidmax', system_uid_max)
message('maximum system UID is @0@'.format(system_uid_max))

conf.set_quoted('NOBODY_USER_NAME', get_option('nobody-user'))
conf.set_quoted('NOBODY_GROUP_NAME', get_option('nobody-group'))

system_gid_max = get_option('system-gid-max')
if system_gid_max == ''
        system_gid_max = run_command(
                awk,
                'BEGIN { gid=999 } /^\s*SYS_GID_MAX\s+/ { gid=$2 } END { print gid }',
                '/etc/login.defs').stdout()
endif
system_gid_max = system_gid_max.to_int()
conf.set('SYSTEM_GID_MAX', system_gid_max)
substs.set('systemgidmax', system_gid_max)
message('maximum system GID is @0@'.format(system_gid_max))

tty_gid = get_option('tty-gid')
conf.set('TTY_GID', tty_gid)
substs.set('TTY_GID', tty_gid)

if get_option('adm-group')
        m4_defines += ['-DENABLE_ADM_GROUP']
endif

if get_option('wheel-group')
        m4_defines += ['-DENABLE_WHEEL_GROUP']
endif

substs.set('DEV_KVM_MODE', get_option('dev-kvm-mode'))

kill_user_processes = get_option('default-kill-user-processes')
conf.set10('KILL_USER_PROCESSES', kill_user_processes)
substs.set('KILL_USER_PROCESSES', kill_user_processes ? 'yes' : 'no')

dns_servers = get_option('dns-servers')
conf.set_quoted('DNS_SERVERS', dns_servers)
substs.set('DNS_SERVERS', dns_servers)

ntp_servers = get_option('ntp-servers')
conf.set_quoted('NTP_SERVERS', ntp_servers)
substs.set('NTP_SERVERS', ntp_servers)

conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())

substs.set('SUSHELL', get_option('debug-shell'))
substs.set('DEBUGTTY', get_option('debug-tty'))

debug = get_option('debug')
if debug != ''
        foreach name : debug.split(',')
                if name == 'hashmap'
                        conf.set('ENABLE_DEBUG_HASHMAP', true)
                elif name == 'mmap-cache'
                        conf.set('ENABLE_DEBUG_MMAP_CACHE', true)
                else
                        message('unknown debug option "@0@", ignoring'.format(name))
                endif
        endforeach
endif

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
                      version : '>= 2.27')

want_seccomp = get_option('seccomp')
if want_seccomp != 'false'
        libseccomp = dependency('libseccomp',
                                version : '>= 2.3.1',
                                required : want_seccomp == 'true')
        if libseccomp.found()
                conf.set('HAVE_SECCOMP', true)
                m4_defines += ['-DHAVE_SECCOMP']
        endif
else
        libseccomp = []
endif

want_selinux = get_option('selinux')
if want_selinux != 'false'
        libselinux = dependency('libselinux',
                                version : '>= 2.1.9',
                                required : want_selinux == 'true')
        if libselinux.found()
                conf.set('HAVE_SELINUX', true)
                m4_defines += ['-DHAVE_SELINUX']
        endif
else
        libselinux = []
endif

want_apparmor = get_option('apparmor')
if want_apparmor != 'false'
        libapparmor = dependency('libapparmor',
                                 required : want_apparmor == 'true')
        if libapparmor.found()
                conf.set('HAVE_APPARMOR', true)
                m4_defines += ['-DHAVE_APPARMOR']
        endif
else
        libapparmor = []
endif

smack_run_label = get_option('smack-run-label')
if smack_run_label != ''
        conf.set_quoted('SMACK_RUN_LABEL', smack_run_label)
        m4_defines += ['-DHAVE_SMACK_RUN_LABEL']
endif

want_polkit = get_option('polkit')
install_polkit = false
install_polkit_pkla = false
if want_polkit != 'false'
        conf.set('ENABLE_POLKIT', true)
        install_polkit = true

        libpolkit = dependency('polkit-gobject-1',
                               required : false)
        if libpolkit.found() and libpolkit.version().version_compare('< 0.106')
                message('Old polkit detected, will install pkla files')
                install_polkit_pkla = true
        endif
endif

want_acl = get_option('acl')
if want_acl != 'false'
        libacl = cc.find_library('acl', required : want_acl == 'true')
        if libacl.found()
                conf.set('HAVE_ACL', true)
                m4_defines += ['-DHAVE_ACL']
        endif
else
        libacl = []
endif

want_audit = get_option('audit')
if want_audit != 'false'
        libaudit = dependency('audit', required : want_audit == 'true')
        conf.set('HAVE_AUDIT', libaudit.found())
else
        libaudit = []
endif

want_blkid = get_option('blkid')
if want_blkid != 'false'
        libblkid = dependency('blkid', required : want_blkid == 'true')
        conf.set('HAVE_BLKID', libblkid.found())
else
        libblkid = []
endif

want_kmod = get_option('kmod')
if want_kmod != 'false'
        libkmod = dependency('libkmod',
                             version : '>= 15',
                             required : want_kmod == 'true')
        conf.set('HAVE_KMOD', libkmod.found())
else
        libkmod = []
endif

want_pam = get_option('pam')
if want_pam != 'false'
        libpam = cc.find_library('pam', required : want_pam == 'true')
        libpam_misc = cc.find_library('pam_misc', required : want_pam == 'true')
        if libpam.found() and libpam_misc.found()
                conf.set('HAVE_PAM', true)
                m4_defines += ['-DHAVE_PAM']
        endif
else
        libpam = []
        libpam_misc = []
endif

want_microhttpd = get_option('microhttpd')
if want_microhttpd != 'false'
        libmicrohttpd = dependency('libmicrohttpd',
                                   version : '>= 0.9.33',
                                   required : want_microhttpd == 'true')
        if libmicrohttpd.found()
                conf.set('HAVE_MICROHTTPD', true)
                m4_defines += ['-DHAVE_MICROHTTPD']
        endif
else
        libmicrohttpd = []
endif

want_libcryptsetup = get_option('libcryptsetup')
if want_libcryptsetup != 'false'
        libcryptsetup = dependency('libcryptsetup',
                                   version : '>= 1.6.0',
                                   required : want_libcryptsetup == 'true')
        conf.set('HAVE_LIBCRYPTSETUP', libcryptsetup.found())
else
        libcryptsetup = []
endif

want_libcurl = get_option('libcurl')
if want_libcurl != 'false'
        libcurl = dependency('libcurl',
                             version : '>= 7.32.0',
                             required : want_libcurl == 'true')
        if libcurl.found()
                conf.set('HAVE_LIBCURL', true)
                m4_defines += ['-DHAVE_LIBCURL']
        endif
else
        libcurl = []
endif

want_libidn = get_option('libidn')
want_libidn2 = get_option('libidn2')
if want_libidn == 'true' and want_libidn2 == 'true'
        error('libidn and libidn2 cannot be requested simultaneously')
endif

if want_libidn != 'false' and want_libidn2 != 'true'
        libidn = dependency('libidn',
                            required : want_libidn == 'true')
        if libidn.found()
                conf.set('HAVE_LIBIDN', true)
                m4_defines += ['-DHAVE_LIBIDN']
        endif
else
        libidn = []
endif
if not conf.get('HAVE_LIBIDN', false) and want_libidn2 != 'false'
        # libidn is used for both libidn and libidn2 objects
        libidn = dependency('libidn2',
                            required : want_libidn2 == 'true')
        if libidn.found()
                conf.set('HAVE_LIBIDN2', true)
                m4_defines += ['-DHAVE_LIBIDN2']
        endif
endif

want_libiptc = get_option('libiptc')
if want_libiptc != 'false'
        libiptc = dependency('libiptc',
                             required : want_libiptc == 'true')
        if libiptc.found()
                conf.set('HAVE_LIBIPTC', true)
                m4_defines += ['-DHAVE_LIBIPTC']
        endif
else
        libiptc = []
endif

want_qrencode = get_option('qrencode')
if want_qrencode != 'false'
        libqrencode = dependency('libqrencode',
                                 required : want_qrencode == 'true')
        conf.set('HAVE_QRENCODE', libqrencode.found())
else
        libqrencode = []
endif

want_gnutls = get_option('gnutls')
if want_gnutls != 'false'
        libgnutls = dependency('gnutls',
                               version : '>= 3.1.4',
                               required : want_gnutls == 'true')
        conf.set('HAVE_GNUTLS', libgnutls.found())
else
        libgnutls = []
endif

want_elfutils = get_option('elfutils')
if want_elfutils != 'false'
        libdw = dependency('libdw',
                           required : want_elfutils == 'true')
        conf.set('HAVE_ELFUTILS', libdw.found())
else
        libdw = []
endif

want_zlib = get_option('zlib')
if want_zlib != 'false'
        libz = dependency('zlib',
                          required : want_zlib == 'true')
        conf.set('HAVE_ZLIB', libz.found())
else
        libz = []
endif

want_bzip2 = get_option('bzip2')
if want_bzip2 != 'false'
        libbzip2 = cc.find_library('bz2',
                                   required : want_bzip2 == 'true')
        conf.set('HAVE_BZIP2', libbzip2.found())
else
        libbzip2 = []
endif

want_xz = get_option('xz')
if want_xz != 'false'
        libxz = dependency('liblzma',
                           required : want_xz == 'true')
        conf.set('HAVE_XZ', libxz.found())
else
        libxz = []
endif

want_lz4 = get_option('lz4')
if want_lz4 != 'false'
        liblz4 = dependency('liblz4',
                            required : want_lz4 == 'true')
        conf.set('HAVE_LZ4', liblz4.found())
else
        liblz4 = []
endif

want_glib = get_option('glib')
if want_glib != 'false'
        libglib =    dependency('glib-2.0',
                                version : '>= 2.22.0',
                                required : want_glib == 'true')
        libgobject = dependency('gobject-2.0',
                                version : '>= 2.22.0',
                                required : want_glib == 'true')
        libgio =     dependency('gio-2.0',
                                required : want_glib == 'true')
        have = libglib.found() and libgobject.found() and libgio.found()
        conf.set('HAVE_GLIB', have)
else
        libglib = []
        libgobject = []
        libgio = []
endif

want_xkbcommon = get_option('xkbcommon')
if want_xkbcommon != 'false'
        libxkbcommon = dependency('xkbcommon',
                                  version : '>= 0.3.0',
                                  required : want_xkbcommon == 'true')
        conf.set('HAVE_XKBCOMMON', libxkbcommon.found())
else
        libxkbcommon = []
endif

want_dbus = get_option('dbus')
if want_dbus != 'false'
        libdbus = dependency('dbus-1',
                             version : '>= 1.3.2',
                             required : want_dbus == 'true')
        conf.set('HAVE_DBUS', libdbus.found())
else
        libdbus = []
endif

want_gcrypt = get_option('gcrypt')
if want_gcrypt != 'false'
        libgcrypt = cc.find_library('gcrypt', required : want_gcrypt == 'true')
        libgpg_error = cc.find_library('gpg-error', required : want_gcrypt == 'true')

        have_deps = libgcrypt.found() and libgpg_error.found()
        conf.set('HAVE_GCRYPT', have_deps)
        if not have_deps
                # link to neither of the libs if one is not found
                libgcrypt = []
                libgpg_error = []
        endif
else
        libgcrypt = []
        libgpg_error = []
endif

default_dnssec = get_option('default-dnssec')
if default_dnssec != 'no' and not conf.get('HAVE_GCRYPT', false)
        message('default-dnssec cannot be set to yes or allow-downgrade when gcrypt is disabled. Setting default-dnssec to no.')
        default_dnssec = 'no'
endif
conf.set('DEFAULT_DNSSEC_MODE',
         'DNSSEC_' + default_dnssec.underscorify().to_upper())
substs.set('DEFAULT_DNSSEC_MODE', default_dnssec)

want_importd = get_option('importd')
if want_importd != 'false'
        have_deps = (conf.get('HAVE_LIBCURL', false) and
                     conf.get('HAVE_ZLIB', false) and
                     conf.get('HAVE_BZIP2', false) and
                     conf.get('HAVE_XZ', false) and
                     conf.get('HAVE_GCRYPT', false))
        conf.set('ENABLE_IMPORTD', have_deps)
        if want_importd == 'true' and not have_deps
                error('importd support was requested, but dependencies are not available')
        endif
endif

want_remote = get_option('remote')
if want_remote != 'false'
        have_deps = [conf.get('HAVE_MICROHTTPD', false),
                     conf.get('HAVE_LIBCURL', false)]
        # sd-j-remote requires µhttpd, and sd-j-upload requires libcurl, so
        # it's possible to build one without the other. Complain only if
        # support was explictly requested. The auxiliary files like sysusers
        # config should be installed when any of the programs are built.
        if want_remote == 'true' and not (have_deps[0] and have_deps[1])
                error('remote support was requested, but dependencies are not available')
        endif
        conf.set('ENABLE_REMOTE', have_deps[0] or have_deps[1])
endif

foreach pair : [['utmp',          'HAVE_UTMP'],
                ['hibernate',     'ENABLE_HIBERNATE'],
                ['environment-d', 'ENABLE_ENVIRONMENT_D'],
                ['binfmt',        'ENABLE_BINFMT'],
                ['coredump',      'ENABLE_COREDUMP'],
                ['resolve',       'ENABLE_RESOLVED'],
                ['logind',        'ENABLE_LOGIND'],
                ['hostnamed',     'ENABLE_HOSTNAMED'],
                ['localed',       'ENABLE_LOCALED'],
                ['machined',      'ENABLE_MACHINED'],
                ['networkd',      'ENABLE_NETWORKD'],
                ['timedated',     'ENABLE_TIMEDATED'],
                ['timesyncd',     'ENABLE_TIMESYNCD'],
                ['myhostname',    'HAVE_MYHOSTNAME'],
                ['firstboot',     'ENABLE_FIRSTBOOT'],
                ['randomseed',    'ENABLE_RANDOMSEED'],
                ['backlight',     'ENABLE_BACKLIGHT'],
                ['vconsole',      'ENABLE_VCONSOLE'],
                ['quotacheck',    'ENABLE_QUOTACHECK'],
                ['sysusers',      'ENABLE_SYSUSERS'],
                ['tmpfiles',      'ENABLE_TMPFILES'],
                ['hwdb',          'ENABLE_HWDB'],
                ['rfkill',        'ENABLE_RFKILL'],
                ['ldconfig',      'ENABLE_LDCONFIG'],
                ['efi',           'ENABLE_EFI'],
                ['tpm',           'SD_BOOT_LOG_TPM'],
                ['ima',           'HAVE_IMA'],
                ['smack',         'HAVE_SMACK'],
                ['gshadow',       'ENABLE_GSHADOW'],
                ['idn',           'ENABLE_IDN'],
                ['nss-systemd',   'ENABLE_NSS_SYSTEMD'],
               ]

        if get_option(pair[0])
                conf.set(pair[1], true)
                m4_defines += ['-D' + pair[1]]
        endif
endforeach

want_tests = get_option('tests')
install_tests = get_option('install-tests')
tests = []

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

        conf.set('ENABLE_EFI', true)
        conf.set_quoted('EFI_MACHINE_TYPE_NAME', EFI_MACHINE_TYPE_NAME)

        conf.set('SD_TPM_PCR', get_option('tpm-pcrindex').to_int())
endif

#####################################################################

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

includes = include_directories('src/basic',
                               'src/shared',
                               'src/systemd',
                               'src/journal',
                               'src/resolve',
                               'src/timesync',
                               'src/login',
                               'src/udev',
                               'src/libudev',
                               'src/core',
                               'src/libsystemd/sd-bus',
                               'src/libsystemd/sd-device',
                               'src/libsystemd/sd-hwdb',
                               'src/libsystemd/sd-id128',
                               'src/libsystemd/sd-netlink',
                               'src/libsystemd/sd-network',
                               'src/libsystemd-network',
                              )

add_project_arguments('-include', 'config.h', language : 'c')

gcrypt_util_sources = files('src/shared/gcrypt-util.h',
                            'src/shared/gcrypt-util.c')

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

libsystemd_sym_path = '@0@/@1@'.format(meson.current_source_dir(), libsystemd_sym)
libsystemd = shared_library(
        'systemd',
        libsystemd_internal_sources,
        journal_internal_sources,
        version : '0.19.0',
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libsystemd_sym_path],
        link_with : [libbasic],
        dependencies : [threads,
                        libgcrypt,
                        librt,
                        libxz,
                        liblz4],
        link_depends : libsystemd_sym,
        install : true,
        install_dir : rootlibdir)

############################################################

# binaries that have --help and are intended for use by humans,
# usually, but not always, installed in /bin.
public_programs = []

subdir('src/libudev')
subdir('src/shared')
subdir('src/core')
subdir('src/udev')
subdir('src/network')

subdir('src/analyze')
subdir('src/journal-remote')
subdir('src/coredump')
subdir('src/hostname')
subdir('src/import')
subdir('src/kernel-install')
subdir('src/locale')
subdir('src/machine')
subdir('src/nspawn')
subdir('src/resolve')
subdir('src/timedate')
subdir('src/timesync')
subdir('src/vconsole')
subdir('src/sulogin-shell')
subdir('src/boot/efi')

subdir('src/test')
subdir('test')

############################################################

# only static linking apart from libdl, to make sure that the
# module is linked to all libraries that it uses.
test_dlopen = executable(
        'test-dlopen',
        test_dlopen_c,
        include_directories : includes,
        link_with : [libbasic],
        dependencies : [libdl])

foreach tuple : [['myhostname', 'HAVE_MYHOSTNAME'],
                 ['systemd',    'ENABLE_NSS_SYSTEMD'],
                 ['mymachines', 'ENABLE_MACHINED'],
                 ['resolve',    'ENABLE_RESOLVED']]

        condition = tuple[1] == '' or conf.get(tuple[1], false)
        if condition
                module = tuple[0]

                sym = 'src/nss-@0@/nss-@0@.sym'.format(module)
                version_script_arg = join_paths(meson.current_source_dir(), sym)

                nss = shared_library(
                        'nss_' + module,
                        'src/nss-@0@/nss-@0@.c'.format(module),
                        version : '2',
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + version_script_arg,
                                     '-Wl,--undefined'],
                        link_with : [libsystemd_internal,
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

                test('dlopen-nss_' + module,
                     test_dlopen,
                     args : [nss.full_path()]) # path to dlopen must include a slash
        endif
endforeach

############################################################

executable('systemd',
           systemd_sources,
           include_directories : includes,
           link_with : [libcore,
                        libshared],
           dependencies : [threads,
                           librt,
                           libseccomp,
                           libselinux,
                           libmount,
                           libblkid],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-analyze',
                 systemd_analyze_sources,
                 include_directories : includes,
                 link_with : [libcore,
                              libshared],
                 dependencies : [threads,
                                 librt,
                                 libseccomp,
                                 libselinux,
                                 libmount,
                                 libblkid],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

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
public_programs += [exe]

exe = executable('journalctl',
                 journalctl_sources,
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads,
                                 libqrencode,
                                 libxz,
                                 liblz4],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

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

executable('systemd-fstab-generator',
           'src/fstab-generator/fstab-generator.c',
           'src/core/mount-setup.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : systemgeneratordir)

if conf.get('ENABLE_ENVIRONMENT_D', false)
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

if conf.get('ENABLE_HIBERNATE', false)
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

if conf.get('HAVE_BLKID', false)
        executable('systemd-gpt-auto-generator',
                   'src/gpt-auto-generator/gpt-auto-generator.c',
                   'src/basic/blkid-util.h',
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
        public_programs += [exe]
endif

if conf.get('ENABLE_RESOLVED', false)
        executable('systemd-resolved',
                   systemd_resolved_sources,
                   gcrypt_util_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads,
                                   libgcrypt,
                                   libgpg_error,
                                   libm,
                                   libidn],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('systemd-resolve',
                         systemd_resolve_sources,
                         gcrypt_util_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads,
                                         libgcrypt,
                                         libgpg_error,
                                         libm,
                                         libidn],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += [exe]
endif

if conf.get('ENABLE_LOGIND', false)
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
        public_programs += [exe]

        exe = executable('systemd-inhibit',
                         'src/login/inhibit.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += [exe]

        if conf.get('HAVE_PAM', false)
                version_script_arg = join_paths(meson.current_source_dir(), pam_systemd_sym)
                pam_systemd = shared_library(
                        'pam_systemd',
                        pam_systemd_c,
                        name_prefix : '',
                        include_directories : includes,
                        link_args : ['-shared',
                                     '-Wl,--version-script=' + version_script_arg],
                        link_with : [libsystemd_internal,
                                     libshared_static],
                        dependencies : [threads,
                                        libpam,
                                        libpam_misc],
                        link_depends : pam_systemd_sym,
                        install : true,
                        install_dir : pamlibdir)

                test('dlopen-pam_systemd',
                     test_dlopen,
                     args : [pam_systemd.full_path()]) # path to dlopen must include a slash
        endif
endif

if conf.get('HAVE_PAM', false)
        executable('systemd-user-sessions',
                   'src/user-sessions/user-sessions.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_EFI', false) and conf.get('HAVE_BLKID', false)
        exe = executable('bootctl',
                         'src/boot/bootctl.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [libblkid],
                         install_rpath : rootlibexecdir,
                         install : true)
        public_programs += [exe]
endif

exe = executable('systemd-socket-activate', 'src/activate/activate.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('systemctl', 'src/systemctl/systemctl.c',
                 include_directories : includes,
                 link_with : [libshared],
                 dependencies : [threads,
                                 libcap,
                                 libselinux,
                                 libxz,
                                 liblz4],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

if conf.get('ENABLE_BACKLIGHT', false)
        executable('systemd-backlight',
                   'src/backlight/backlight.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RFKILL', false)
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

if conf.get('HAVE_LIBCRYPTSETUP', false)
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

if conf.get('HAVE_SYSV_COMPAT', false)
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

if conf.get('ENABLE_HOSTNAMED', false)
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
        public_programs += [exe]
endif

if conf.get('ENABLE_LOCALED', false)
        if conf.get('HAVE_XKBCOMMON', false)
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
        public_programs += [exe]
endif

if conf.get('ENABLE_TIMEDATED', false)
        executable('systemd-timedated',
                   'src/timedate/timedated.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)

        exe = executable('timedatectl',
                         'src/timedate/timedatectl.c',
                         include_directories : includes,
                         install_rpath : rootlibexecdir,
                         link_with : [libshared],
                         install : true)
        public_programs += [exe]
endif

if conf.get('ENABLE_TIMESYNCD', false)
        executable('systemd-timesyncd',
                   systemd_timesyncd_sources,
                   include_directories : includes,
                   link_with : [libshared],
                   dependencies : [threads,
                                   libm],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_MACHINED', false)
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
        public_programs += [exe]
endif

if conf.get('ENABLE_IMPORTD', false)
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
                                  dependencies : [libcurl,
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
        public_programs += [systemd_pull, systemd_import, systemd_export]
endif

if conf.get('ENABLE_REMOTE', false) and conf.get('HAVE_LIBCURL', false)
        exe = executable('systemd-journal-upload',
                         systemd_journal_upload_sources,
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [threads,
                                         libcurl,
                                         libgnutls,
                                         libxz,
                                         liblz4],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootlibexecdir)
        public_programs += [exe]
endif

if conf.get('ENABLE_REMOTE', false) and conf.get('HAVE_MICROHTTPD', false)
        s_j_remote = executable('systemd-journal-remote',
                                systemd_journal_remote_sources,
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

if conf.get('ENABLE_COREDUMP', false)
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
        public_programs += [exe]
endif

if conf.get('ENABLE_BINFMT', false)
        exe = executable('systemd-binfmt',
                         'src/binfmt/binfmt.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootlibexecdir)
        public_programs += [exe]

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(binfmtdir))
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'binfmt.d')))
endif

if conf.get('ENABLE_VCONSOLE', false)
        executable('systemd-vconsole-setup',
                   'src/vconsole/vconsole-setup.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RANDOMSEED', false)
        executable('systemd-random-seed',
                   'src/random-seed/random-seed.c',
                   include_directories : includes,
                   link_with : [libshared],
                   install_rpath : rootlibexecdir,
                   install : true,
                   install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_FIRSTBOOT', false)
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
           'src/core/mount-setup.c',
           'src/core/mount-setup.h',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-machine-id-setup',
           'src/machine-id-setup/machine-id-setup-main.c',
           'src/core/machine-id-setup.c',
           'src/core/machine-id-setup.h',
           include_directories : includes,
           link_with : [libshared],
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

executable('systemd-sleep',
           'src/sleep/sleep.c',
           include_directories : includes,
           link_with : [libshared],
           install_rpath : rootlibexecdir,
           install : true,
           install_dir : rootlibexecdir)

exe = executable('systemd-sysctl',
                 'src/sysctl/sysctl.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootlibexecdir)
public_programs += [exe]

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
public_programs += [exe]

exe = executable('systemd-delta',
                 'src/delta/delta.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('systemd-escape',
                 'src/escape/escape.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

exe = executable('systemd-notify',
                 'src/notify/notify.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

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

exe = executable('systemd-path',
                 'src/path/path.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('systemd-ask-password',
                 'src/ask-password/ask-password.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

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
public_programs += [exe]

exe = executable('systemd-cgls',
                 'src/cgls/cgls.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('systemd-cgtop',
                 'src/cgtop/cgtop.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

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
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

meson.add_install_script(meson_make_symlink,
                         'systemd-mount', join_paths(bindir, 'systemd-umount'))

exe = executable('systemd-run',
                 'src/run/run.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('systemd-stdio-bridge',
                 'src/stdio-bridge/stdio-bridge.c',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

exe = executable('busctl',
                 'src/busctl/busctl.c',
                 'src/busctl/busctl-introspect.c',
                 'src/busctl/busctl-introspect.h',
                 include_directories : includes,
                 link_with : [libshared],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

if conf.get('ENABLE_SYSUSERS', false)
        exe = executable('systemd-sysusers',
                         'src/sysusers/sysusers.c',
                         include_directories : includes,
                         link_with : [libshared],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += [exe]
endif

if conf.get('ENABLE_TMPFILES', false)
        exe = executable('systemd-tmpfiles',
                         'src/tmpfiles/tmpfiles.c',
                         include_directories : includes,
                         link_with : [libshared],
                         dependencies : [libacl],
                         install_rpath : rootlibexecdir,
                         install : true,
                         install_dir : rootbindir)
        public_programs += [exe]
endif

if conf.get('ENABLE_HWDB', false)
        exe = executable('systemd-hwdb',
                         'src/hwdb/hwdb.c',
                         'src/libsystemd/sd-hwdb/hwdb-internal.h',
                         include_directories : includes,
                         link_with : [libudev_internal],
                         install_rpath : udev_rpath,
                         install : true,
                         install_dir : rootbindir)
        public_programs += [exe]
endif

if conf.get('ENABLE_QUOTACHECK', false)
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
public_programs += [exe]

exe = executable('systemd-udevd',
                 systemd_udevd_sources,
                 include_directories : includes,
                 c_args : ['-DLOG_REALM=LOG_REALM_UDEV'],
                 link_with : [libudev_core,
                              libsystemd_network,
                              libudev_internal],
                 dependencies : [threads,
                                 libkmod,
                                 libidn,
                                 libacl,
                                 libblkid],
                 install_rpath : udev_rpath,
                 install : true,
                 install_dir : rootlibexecdir)
public_programs += [exe]

exe = executable('udevadm',
                 udevadm_sources,
                 include_directories : includes,
                 link_with : [libudev_core,
                              libsystemd_network,
                              libudev_internal],
                 dependencies : [threads,
                                 libkmod,
                                 libidn,
                                 libacl,
                                 libblkid],
                 install_rpath : udev_rpath,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

executable('systemd-shutdown',
           systemd_shutdown_sources,
           include_directories : includes,
           link_with : [libshared],
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

if conf.get('HAVE_KMOD', false)
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
                 'src/core/mount-setup.c', # FIXME: use a variable?
                 'src/core/mount-setup.h',
                 'src/core/loopback-setup.c',
                 'src/core/loopback-setup.h',
                 include_directories : [includes, include_directories('src/nspawn')],
                 link_with : [libshared],
                 dependencies : [libacl,
                                 libblkid,
                                 libseccomp,
                                 libselinux],
                 install_rpath : rootlibexecdir,
                 install : true)
public_programs += [exe]

if conf.get('ENABLE_NETWORKD', false)
        executable('systemd-networkd',
                   systemd_networkd_sources,
                   include_directories : includes,
                   link_with : [libnetworkd_core,
                                libsystemd_network,
                                libudev_internal,
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
endif

exe = executable('networkctl',
                 networkctl_sources,
                 include_directories : includes,
                 link_with : [libsystemd_network,
                              libshared],
                 install_rpath : rootlibexecdir,
                 install : true,
                 install_dir : rootbindir)
public_programs += [exe]

############################################################

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

        if condition == '' or conf.get(condition, false)
                exe = executable(
                        name,
                        sources,
                        include_directories : incs,
                        link_with : link_with,
                        dependencies : dependencies,
                        c_args : defs,
                        install_rpath : rootlibexecdir,
                        install : install_tests,
                        install_dir : join_paths(testsdir, type))

                if type == 'manual'
                        message('@0@ is a manual test'.format(name))
                elif type == 'unsafe' and want_tests != 'unsafe'
                        message('@0@ is an unsafe test'.format(name))
                else
                        test(name, exe,
                             env : test_env,
                             timeout : timeout)
                endif
        else
                message('Not compiling @0@ because @1@ is not true'.format(name, condition))
        endif
endforeach

test_libsystemd_sym = executable(
        'test-libsystemd-sym',
        test_libsystemd_sym_c,
        include_directories : includes,
        link_with : [libsystemd],
        install : install_tests,
        install_dir : testsdir)
test('test-libsystemd-sym',
     test_libsystemd_sym)

test_libudev_sym = executable(
        'test-libudev-sym',
        test_libudev_sym_c,
        include_directories : includes,
        c_args : ['-Wno-deprecated-declarations'],
        link_with : [libudev],
        install : install_tests,
        install_dir : testsdir)
test('test-libudev-sym',
     test_libudev_sym)

############################################################

make_directive_index_py = find_program('tools/make-directive-index.py')
make_man_index_py = find_program('tools/make-man-index.py')
xml_helper_py = find_program('tools/xml_helper.py')
hwdb_update_sh = find_program('tools/meson-hwdb-update.sh')

subdir('units')
subdir('sysctl.d')
subdir('sysusers.d')
subdir('tmpfiles.d')
subdir('rules')
subdir('hwdb')
subdir('network')
subdir('man')
subdir('shell-completion/bash')
subdir('shell-completion/zsh')
subdir('docs/sysvinit')
subdir('docs/var-log')

# FIXME: figure out if the warning is true:
# https://github.com/mesonbuild/meson/wiki/Reference-manual#install_subdir
install_subdir('factory/etc',
               install_dir : factorydir)


install_data('xorg/50-systemd-user.sh',
             install_dir : xinitrcdir)
install_data('system-preset/90-systemd.preset',
             install_dir : systempresetdir)
install_data('README',
             'NEWS',
             'CODING_STYLE',
             'DISTRO_PORTING',
             'ENVIRONMENT.md',
             'LICENSE.GPL2',
             'LICENSE.LGPL2.1',
             'src/libsystemd/sd-bus/GVARIANT-SERIALIZATION',
             install_dir : docdir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemdstatedir))
meson.add_install_script('sh', '-c', 'touch $DESTDIR@0@'.format(prefixdir))

############################################################

meson_check_help = find_program('tools/meson-check-help.sh')

foreach exec : public_programs
        name = exec.full_path().split('/')[-1]
        test('check-help-' + name,
             meson_check_help,
             args : [exec.full_path()])
endforeach

############################################################

if git.found()
        all_files = run_command(
                git,
                ['--git-dir=@0@/.git'.format(meson.source_root()),
                 'ls-files',
                 ':/*.[ch]'])
        all_files = files(all_files.stdout().split())

        run_target(
                'tags',
                input : all_files,
                command : ['env', 'etags', '-o', '@0@/TAGS'.format(meson.source_root())] + all_files)
        run_target(
                'ctags',
                input : all_files,
                command : ['env', 'ctags', '-o', '@0@/tags'.format(meson.source_root())] + all_files)
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
                ['--git-dir=@0@/.git'.format(meson.source_root()),
                 'rev-parse', 'HEAD']).stdout().strip()
        git_head_short = run_command(
                git,
                ['--git-dir=@0@/.git'.format(meson.source_root()),
                 'rev-parse', '--short=7', 'HEAD']).stdout().strip()

        run_target(
                'git-snapshot',
                command : ['git', 'archive',
                           '-o', '@0@/systemd-@1@.tar.gz'.format(meson.source_root(),
                                                                 git_head_short),
                           '--prefix', 'systemd-@0@/'.format(git_head),
                           'HEAD'])
endif

############################################################

status = [
        '@0@ @1@'.format(meson.project_name(), meson.project_version()),

        'prefix:                            @0@'.format(prefixdir),
        'rootprefix:                        @0@'.format(rootprefixdir),
        'sysconf dir:                       @0@'.format(sysconfdir),
        'includedir:                        @0@'.format(includedir),
        'lib dir:                           @0@'.format(libdir),
        'rootlib dir:                       @0@'.format(rootlibdir),
        'SysV init scripts:                 @0@'.format(sysvinit_path),
        'SysV rc?.d directories:            @0@'.format(sysvrcnd_path),
        'PAM modules dir:                   @0@'.format(pamlibdir),
        'PAM configuration dir:             @0@'.format(pamconfdir),
        'RPM macros dir:                    @0@'.format(rpmmacrosdir),
        'D-Bus policy dir:                  @0@'.format(dbuspolicydir),
        'D-Bus session dir:                 @0@'.format(dbussessionservicedir),
        'D-Bus system dir:                  @0@'.format(dbussystemservicedir),
        'bash completions dir:              @0@'.format(bashcompletiondir),
        'zsh completions dir:               @0@'.format(zshcompletiondir),
        'extra start script:                @0@'.format(get_option('rc-local')),
        'extra stop script:                 @0@'.format(get_option('halt-local')),
        'debug shell:                       @0@ @ @1@'.format(get_option('debug-shell'),
                                                              get_option('debug-tty')),
        'TTY GID:                           @0@'.format(tty_gid),
        'maximum system UID:                @0@'.format(system_uid_max),
        'maximum system GID:                @0@'.format(system_gid_max),
        '/dev/kvm access mode:              @0@'.format(get_option('dev-kvm-mode')),
        'certificate root:                  @0@'.format(get_option('certificate-root')),
        'support URL:                       @0@'.format(support_url),
        'nobody user name:                  @0@'.format(get_option('nobody-user')),
        'nobody group name:                 @0@'.format(get_option('nobody-group')),
        'fallback hostname:                 @0@'.format(get_option('fallback-hostname')),

        'default DNSSEC mode:               @0@'.format(default_dnssec),
        'default cgroup hierarchy:          @0@'.format(default_hierarchy),
        'default KillUserProcesses setting: @0@'.format(kill_user_processes)]

alt_dns_servers = '\n                                            '.join(dns_servers.split(' '))
alt_ntp_servers = '\n                                            '.join(ntp_servers.split(' '))
status += [
        'default DNS servers:               @0@'.format(alt_dns_servers),
        'default NTP servers:               @0@'.format(alt_ntp_servers)]

alt_time_epoch = run_command('date', '-Is', '-u', '-d',
                             '@@0@'.format(time_epoch)).stdout().strip()
status += [
        'time epoch:                        @0@ (@1@)'.format(time_epoch, alt_time_epoch)]

# TODO:
# CFLAGS:   ${OUR_CFLAGS} ${CFLAGS}
# CPPFLAGS: ${OUR_CPPFLAGS} ${CPPFLAGS}
# LDFLAGS:  ${OUR_LDFLAGS} ${LDFLAGS}

if conf.get('ENABLE_EFI', false)
        status += [
                'efi arch:                          @0@'.format(efi_arch)]

        if have_gnu_efi
                status += [
                        'EFI machine type:                  @0@'.format(EFI_MACHINE_TYPE_NAME),
                        'EFI CC                             @0@'.format(efi_cc),
                        'EFI libdir:                        @0@'.format(efi_libdir),
                        'EFI ldsdir:                        @0@'.format(efi_ldsdir),
                        'EFI includedir:                    @0@'.format(efi_incdir)]
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
        ['libcurl'],
        ['idn'],
        ['libidn2'],
        ['libidn'],
        ['nss-systemd'],
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
        ['importd'],
        ['hostnamed'],
        ['timedated'],
        ['timesyncd'],
        ['localed'],
        ['networkd'],
        ['resolved'],
        ['coredump'],
        ['polkit'],
        ['legacy pkla',      install_polkit_pkla],
        ['efi'],
        ['gnu-efi',          have_gnu_efi],
        ['kmod'],
        ['xkbcommon'],
        ['blkid'],
        ['dbus'],
        ['glib'],
        ['nss-myhostname',   conf.get('HAVE_MYHOSTNAME', false)],
        ['hwdb'],
        ['tpm'],
        ['man pages',        want_man],
        ['html pages',       want_html],
        ['man page indices', want_man and have_lxml],
        ['split /usr',       conf.get('HAVE_SPLIT_USR', false)],
        ['SysV compat'],
        ['utmp'],
        ['ldconfig'],
        ['hibernate'],
        ['adm group',        get_option('adm-group')],
        ['wheel group',      get_option('wheel-group')],
        ['gshadow'],
        ['debug hashmap'],
        ['debug mmap cache'],
]

        cond = tuple.get(1, '')
        if cond == ''
                ident1 = 'HAVE_' + tuple[0].underscorify().to_upper()
                ident2 = 'ENABLE_' + tuple[0].underscorify().to_upper()
                cond = conf.get(ident1, false) or conf.get(ident2, false)
        endif
        if cond
                found += [tuple[0]]
        else
                missing += [tuple[0]]
        endif
endforeach

status += [
        'enabled features: @0@'.format(', '.join(found)),
        'disabled features: @0@'.format(', '.join(missing))]
message('\n         '.join(status))

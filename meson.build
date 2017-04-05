# -*- mode: meson -*-

project('systemd', 'c',
        version : '233',
        license : 'LGPLv2+',
        default_options: [
          'c_std=gnu99',
          'prefix=/usr',
          'sysconfdir=/etc',
          'localstatedir=/var',
        ],
        meson_version : '>= 0.39.1',
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

if get_option('split-usr')
  conf.set('HAVE_SPLIT_USR', 1)
  rootprefixdir = '/'
else
  rootprefixdir = '/usr'
endif

sysvinit_path = get_option('sysvinit-path')
sysvrcnd_path = get_option('sysvrcnd-path')
if sysvinit_path != '' or sysvrcnd_path != ''
  conf.set('HAVE_SYSV_COMPAT', 1,
           description : 'SysV init scripts and rcN.d links are supported')
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
pkgconfigdatadir = datadir + '/pkgconfig'
pkgconfiglibdir = libdir + '/pkgconfig'
polkitpolicydir = datadir + '/polkit-1/actions'
polkitrulesdir = datadir + '/polkit-1/rules.d'
polkitpkladir = localstatedir + '/lib/polkit-1/localauthority/10-vendor.d'
varlogdir = localstatedir + '/log'
xinitrcdir = sysconfdir + '/X11/xinit/xinitrc.d'
rpmmacrosdir = get_option('rpmmacrosdir')

# Our own paths
pkgdatadir = datadir + '/systemd'
environmentdir = prefixdir + '/lib/environment.d'
pkgsysconfdir = sysconfdir + '/systemd'
userunitdir = prefixdir + '/lib/systemd/user'
userpresetdir = prefixdir + '/lib/systemd/user-preset'
tmpfilesdir = prefixdir + '/lib/tmpfiles.d'
sysusersdir = prefixdir + '/lib/sysusers.d'
sysctldir = prefixdir + '/lib/sysctl.d'
binfmtdir = prefixdir + '/lib/binfmt.d'
modulesloaddir = prefixdir + '/lib/modules-load.d'
networkdir = rootprefixdir + '/lib/systemd/network'
pkgincludedir = includedir + '/systemd'
systemgeneratordir = rootlibexecdir + '/system-generators'
usergeneratordir = prefixdir + '/lib/systemd/user-generators'
systemenvgeneratordir = prefixdir + '/lib/systemd/system-environment-generators'
userenvgeneratordir = prefixdir + '/lib/systemd/user-environment-generators'
systemshutdowndir = rootlibexecdir + '/system-shutdown'
systemsleepdir = rootlibexecdir + '/system-sleep'
systemunitdir = rootprefixdir + '/lib/systemd/system'
systempresetdir = rootprefixdir + '/lib/systemd/system-preset'
udevlibexecdir = rootprefixdir + '/lib/udev'
udevhomedir = udevlibexecdir + ''
udevrulesdir = udevlibexecdir + '/rules.d'
udevhwdbdir = udevlibexecdir + '/hwdb.d'
catalogdir = prefixdir + '/lib/systemd/catalog'
kernelinstalldir = prefixdir + '/lib/kernel/install.d'
factorydir = datadir + '/factory'
docdir = datadir + '/doc/systemd'
bootlibdir = prefixdir + '/lib/systemd/boot/efi'
testsdir = prefixdir + '/lib/systemd/tests'
systemdstatedir = localstatedir + '/lib/systemd'
catalogstatedir = systemdstatedir + '/catalog'

dbuspolicydir = get_option('dbuspolicydir')
if dbuspolicydir == ''
  dbuspolicydir = datadir + '/dbus-1/system.d'
endif

dbussessionservicedir = get_option('dbussessionservicedir')
if dbussessionservicedir == ''
  dbussessionservicedir = datadir + '/dbus-1/services'
endif

dbussystemservicedir = get_option('dbussystemservicedir')
if dbussystemservicedir == ''
  dbussystemservicedir = datadir + '/dbus-1/system-services'
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
  pamlibdir = rootlibdir + '/security'
endif

pamconfdir = get_option('pamconfdir')
if pamconfdir == ''
  pamconfdir = sysconfdir + '/pam.d'
endif

conf.set_quoted('PKGSYSCONFDIR',                              pkgsysconfdir)
conf.set_quoted('SYSTEM_CONFIG_UNIT_PATH',                    pkgsysconfdir + '/system')
conf.set_quoted('SYSTEM_DATA_UNIT_PATH',                      systemunitdir)
conf.set_quoted('SYSTEM_SYSVINIT_PATH',                       sysvinit_path)
conf.set_quoted('SYSTEM_SYSVRCND_PATH',                       sysvrcnd_path)
conf.set_quoted('USER_CONFIG_UNIT_PATH',                      pkgsysconfdir + '/user')
conf.set_quoted('USER_DATA_UNIT_PATH',                        userunitdir)
conf.set_quoted('CERTIFICATE_ROOT',                           get_option('certificate-root'))
conf.set_quoted('CATALOG_DATABASE',                           catalogstatedir + '/database')
conf.set_quoted('SYSTEMD_CGROUP_AGENT_PATH',                  rootlibexecdir + '/systemd-cgroups-agent')
conf.set_quoted('SYSTEMD_BINARY_PATH',                        rootlibexecdir + '/systemd')
conf.set_quoted('SYSTEMD_FSCK_PATH',                          rootlibexecdir + '/systemd-fsck')
conf.set_quoted('SYSTEMD_SHUTDOWN_BINARY_PATH',               rootlibexecdir + '/systemd-shutdown')
conf.set_quoted('SYSTEMD_SLEEP_BINARY_PATH',                  rootlibexecdir + '/systemd-sleep')
conf.set_quoted('SYSTEMCTL_BINARY_PATH',                      rootbindir + '/systemctl')
conf.set_quoted('SYSTEMD_TTY_ASK_PASSWORD_AGENT_BINARY_PATH', rootbindir + '/systemd-tty-ask-password-agent')
conf.set_quoted('SYSTEMD_STDIO_BRIDGE_BINARY_PATH',           bindir + '/systemd-stdio-bridge')
conf.set_quoted('ROOTPREFIX',                                 rootprefixdir)
conf.set_quoted('RANDOM_SEED_DIR',                            localstatedir + '/lib/systemd/')
conf.set_quoted('RANDOM_SEED',                                localstatedir + '/lib/systemd/random-seed')
conf.set_quoted('SYSTEMD_CRYPTSETUP_PATH',                    rootlibexecdir + '/systemd-cryptsetup')
conf.set_quoted('SYSTEM_GENERATOR_PATH',                      systemgeneratordir)
conf.set_quoted('USER_GENERATOR_PATH',                        usergeneratordir)
conf.set_quoted('SYSTEM_ENV_GENERATOR_PATH',                  systemenvgeneratordir)
conf.set_quoted('USER_ENV_GENERATOR_PATH',                    userenvgeneratordir)
conf.set_quoted('SYSTEM_SHUTDOWN_PATH',                       systemshutdowndir)
conf.set_quoted('SYSTEM_SLEEP_PATH',                          systemsleepdir)
conf.set_quoted('SYSTEMD_KBD_MODEL_MAP',                      pkgdatadir + '/kbd-model-map')
conf.set_quoted('SYSTEMD_LANGUAGE_FALLBACK_MAP',              pkgdatadir + '/language-fallback-map')
conf.set_quoted('UDEVLIBEXECDIR',                             udevlibexecdir)
conf.set_quoted('POLKIT_AGENT_BINARY_PATH',                   bindir + '/pkttyagent')
conf.set_quoted('LIBDIR',                                     libdir)
conf.set_quoted('ROOTLIBDIR',                                 rootlibdir)
conf.set_quoted('ROOTLIBEXECDIR',                             rootlibexecdir)
conf.set_quoted('BOOTLIBDIR',                                 bootlibdir)
conf.set_quoted('SYSTEMD_PULL_PATH',                          rootlibexecdir + '/systemd-pull')
conf.set_quoted('SYSTEMD_IMPORT_PATH',                        rootlibexecdir + '/systemd-import')
conf.set_quoted('SYSTEMD_EXPORT_PATH',                        rootlibexecdir + '/systemd-export')
conf.set_quoted('VENDOR_KEYRING_PATH',                        rootlibexecdir + '/import-pubring.gpg')
conf.set_quoted('USER_KEYRING_PATH',                          pkgsysconfdir + '/import-pubring.gpg')
conf.set_quoted('DOCUMENT_ROOT',                              pkgdatadir + '/gatewayd')

conf.set_quoted('ABS_BUILD_DIR',                              meson.build_root())
conf.set_quoted('ABS_SRC_DIR',                                meson.source_root())

substs.set('prefix',                                          prefixdir)
substs.set('pkgsysconfdir',                                   pkgsysconfdir)
substs.set('rootlibexecdir',                                  rootlibexecdir)
substs.set('systemunitdir',                                   systemunitdir)
substs.set('userunitdir',                                     userunitdir)
substs.set('systempresetdir',                                 systempresetdir)
substs.set('userpresetdir',                                   userpresetdir)
substs.set('udevhwdbdir',                                     udevhwdbdir)
substs.set('udevrulesdir',                                    udevrulesdir)
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

#####################################################################

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

foreach arg : ['-Wundef',
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
               '-Wno-unused-parameter',
               '-Wno-missing-field-initializers',
               '-Wno-unused-result',
               '-Wno-format-signedness',
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

if cc.compiles('
   #include <time.h>
   #include <inttypes.h>
   typedef uint64_t usec_t;
   usec_t now(clockid_t clock);
   int main(void) {
           struct timespec now;
           return 0;
   }
')
  # TODO: message?
  add_project_arguments('-Werror=shadow', language : 'c')
endif

if cc.get_id() == 'clang'
  foreach arg : ['-Wno-typedef-redefinition',
                 '-Wno-gnu-variable-sized-type-not-at-end',
                ]
    if cc.has_argument(arg)
      add_project_arguments(arg, language : 'c')
    endif
  endforeach
endif

# --as-needed and --no-undefined are provided by meson by default,
# run mesonconf to see what is enabled
foreach arg : ['-Wl,-z,relro',
               '-Wl,-z,now',
               '-pie',
               '-Wl,-fuse-ld=gold',
              ]
  if cc.has_argument(arg)
    add_project_link_arguments(arg, language : 'c')
  endif
endforeach

#####################################################################
# compilation result tests

conf.set('_GNU_SOURCE', 1)
conf.set('__SANE_USERSPACE_TYPES__', 1)

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
  if cc.sizeof(decl, prefix : decl_headers) > 0
    # We get -1 if the size cannot be determined
    conf.set('HAVE_' + decl.underscorify().to_upper(), 1)
  endif
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
    conf.set('HAVE_' + ident.to_upper(), 1)
    skip = true
  endif
endforeach

foreach ident : [
  ['memfd_create',      '''#include <sys/memfd.h>'''],
  ['gettid',            '''#include <sys/types.h>'''],
  ['pivot_root',        '''#include <stdlib.h>'''],        # no known header declares pivot_root
  ['name_to_handle_at', '''#define _GNU_SOURCE
                           #include <sys/types.h>
                           #include <sys/stat.h>
                           #include <fcntl.h>'''],
  ['setns',             '''#define _GNU_SOURCE
                           #include <sched.h>'''],
  ['getrandom',         '''#include <sys/random.h>'''],
  ['renameat2',         '''#include <stdio.h>'''],
  ['kcmp',              '''#include <linux/kcmp.h>'''],
  ['keyctl',            '''#include <sys/types.h>
                           #include <keyutils.h>'''],
  ['copy_file_range',   '''#include <sys/syscall.h>
                           #include <unistd.h>'''],
  ['explicit_bzero' ,   '''#include <strings.h>'''],
  ]

  have = cc.has_function(ident[0], prefix : ident[1])
  conf.set10('HAVE_DECL_' + ident[0].to_upper(), have)
endforeach

#####################################################################

sed = find_program('sed')
grep = find_program('grep')
awk = find_program('awk')
m4 = find_program('m4')
stat = find_program('stat')

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
    exe = find_program(prog[0], '/usr/sbin/' + prog[0], '/sbin/' + prog[0], required: false)
    path = exe.found() ? exe.path() : prog[1]
  endif
  name = prog.length() > 2 ? prog[2] : prog[0].to_upper()
  conf.set_quoted(name, path)
endforeach

# TODO: add ln --relative check
# AS_IF([! ln --relative --help > /dev/null 2>&1], [AC_MSG_ERROR([*** ln doesn't support --relative ***])])

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
conf.set('GPERF_LEN_TYPE', gperf_len_type, description : 'The type of gperf "len" parameter')

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
  if cc.has_header(header)
    conf.set('HAVE_' + header.underscorify().to_upper(), 1)
  endif
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
message('Maximum system UID is @0@'.format(system_uid_max))

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
message('Maximum system GID is @0@'.format(system_gid_max))

tty_gid = get_option('tty-gid')
conf.set('TTY_GID', tty_gid)
m4_defines += ['-DTTY_GID=' + tty_gid]

if get_option('adm-group')
  m4_defines += ['-DENABLE_ADM_GROUP']
endif

if get_option('wheel-group')
  m4_defines += ['-DENABLE_WHEEL_GROUP']
endif

substs.set('DEV_KVM_MODE', get_option('dev-kvm-mode'))

conf.set10('KILL_USER_PROCESSES', get_option('default-kill-user-processes'))

default_dnssec = get_option('default-dnssec')
conf.set('DEFAULT_DNSSEC_MODE',
         'DNSSEC_' + default_dnssec.underscorify().to_upper())

conf.set_quoted('DNS_SERVERS', get_option('dns-servers'))

conf.set_quoted('NTP_SERVERS', get_option('ntp-servers'))

conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())

#####################################################################

threads = dependency('threads')
librt = cc.find_library('rt')
libm = cc.find_library('m')
libdl = cc.find_library('dl')
libcrypt = cc.find_library('crypt')

libcap = dependency('libcap')
libmount = dependency('mount',
                      version : '>= 2.27')

want_seccomp = get_option('seccomp')
if want_seccomp != 'no'
  libseccomp = dependency('libseccomp',
                          required : want_seccomp == 'yes')
  if libseccomp.found()
    conf.set('HAVE_SECCOMP', 1)
    m4_defines += ['-DHAVE_SECCOMP']
  endif
else
  libseccomp = []
endif

want_selinux = get_option('selinux')
if want_selinux != 'no'
  libselinux = dependency('libselinux',
                          version : '>= 2.1.9',
                          required : want_selinux == 'yes')
  if libselinux.found()
    conf.set('HAVE_SELINUX', 1)
    m4_defines += ['-DHAVE_SELINUX']
  endif
else
  libselinux = []
endif

want_apparmor = get_option('apparmor')
if want_apparmor != 'no'
  libapparmor = dependency('libapparmor',
                           required : want_apparmor == 'yes')
  if libapparmor.found()
    conf.set('HAVE_APPARMOR', 1)
    m4_defines += ['-DHAVE_APPARMOR']
  endif
else
  libapparmor = []
endif

want_smack = get_option('smack')
if want_smack != 'no'
  libsmack = dependency('libsmack',
                        required : want_smack == 'yes')
  if libsmack.found()
    conf.set('HAVE_SMACK', 1)
    m4_defines += ['-DHAVE_SMACK']
  endif
else
  libsmack = []
endif

smack_run_label = get_option('smack-run-label')
if smack_run_label != ''
  conf.set_quoted('SMACK_RUN_LABEL', smack_run_label)
  m4_defines += ['-DHAVE_SMACK_RUN_LABEL']
endif

want_audit = get_option('audit')
if want_audit != 'no'
  libaudit = dependency('audit', required : want_audit == 'yes')
  if libaudit.found()
    conf.set('HAVE_AUDIT', 1)
  endif
else
  libaudit = []
endif

want_blkid = get_option('blkid')
if want_blkid != 'no'
  libblkid = dependency('blkid', required : want_blkid == 'yes')
  if libblkid.found()
    conf.set('HAVE_BLKID', 1)
  endif
else
  libblkid = []
endif

want_kmod = get_option('kmod')
if want_kmod != 'no'
  libkmod = dependency('libkmod',
                       version : '>= 15',
                       required : want_kmod == 'yes')
  if libkmod.found()
    conf.set('HAVE_KMOD', 1)
  endif
else
  libkmod = []
endif

want_pam = get_option('pam')
if want_pam != 'no'
  libpam = cc.find_library('pam', required : want_pam == 'yes')
  libpam_misc = cc.find_library('pam_misc', required : want_pam == 'yes')
  if libpam.found() and libpam_misc.found()
    conf.set('HAVE_PAM', 1)
    m4_defines += ['-DHAVE_PAM']
  endif
else
  libpam = []
  libpam_misc = []
endif

want_microhttpd = get_option('microhttpd')
if want_microhttpd != 'no'
  libmicrohttpd = dependency('libmicrohttpd',
                             version : '>= 0.9.33',
                             required : want_microhttpd == 'yes')
  if libmicrohttpd.found()
    conf.set('HAVE_MICROHTTPD', 1)
    m4_defines += ['-DHAVE_MICROHTTPD']
  endif
else
  libmicrohttpd = []
endif

want_libcryptsetup = get_option('libcryptsetup')
if want_libcryptsetup != 'no'
  libcryptsetup = dependency('libcryptsetup',
                             version : '>= 1.6.0',
                             required : want_libcryptsetup == 'yes')
  if libcryptsetup.found()
    conf.set('HAVE_LIBCRYPTSETUP', 1)
  endif
else
  libcryptsetup = []
endif

want_libcurl = get_option('libcurl')
if want_libcurl != 'no'
  libcurl = dependency('libcurl',
                       version : '>= 7.32.0',
                       required : want_libcurl == 'yes')
  if libcurl.found()
    conf.set('HAVE_LIBCURL', 1)
    m4_defines += ['-DHAVE_LIBCURL']
  endif
else
  libcurl = []
endif

want_libidn = get_option('libidn')
if want_libidn != 'no'
  libidn = dependency('libidn',
                      required : want_libidn == 'yes')
  if libidn.found()
    conf.set('HAVE_LIBIDN', 1)
    m4_defines += ['-DHAVE_LIBIDN']
  endif
else
  libidn = []
endif

want_libiptc = get_option('libiptc')
if want_libiptc != 'no'
  libiptc = dependency('libiptc',
                       required : want_libiptc == 'yes')
  if libiptc.found()
    conf.set('HAVE_LIBIPTC', 1)
    m4_defines += ['-DHAVE_LIBIPTC']
  endif
else
  libiptc = []
endif

want_qrencode = get_option('qrencode')
if want_qrencode != 'no'
  libqrencode = dependency('libqrencode',
                           required : want_qrencode == 'yes')
  if libqrencode.found()
    conf.set('HAVE_QRENCODE', 1)
  endif
else
  libqrencode = []
endif

want_gnutls = get_option('gnutls')
if want_gnutls != 'no'
  libgnutls = dependency('gnutls',
                         version : '>= 3.1.4',
                         required : want_gnutls == 'yes')
  if libgnutls.found()
    conf.set('HAVE_GNUTLS', 1)
  endif
else
  libgnutls = []
endif

want_elfutils = get_option('elfutils')
if want_elfutils != 'no'
  libdw = dependency('libdw',
                     required : want_elfutils == 'yes')
  if libdw.found()
    conf.set('HAVE_ELFUTILS', 1)
  endif
else
  libdw = []
endif

want_zlib = get_option('zlib')
if want_zlib != 'no'
  libz = dependency('zlib',
                    required : want_zlib == 'yes')
  if libz.found()
    conf.set('HAVE_ZLIB', 1)
  endif
else
  libz = []
endif

want_bzip2 = get_option('bzip2')
if want_bzip2 != 'no'
  libbzip2 = cc.find_library('bz2',
                             required : want_bzip2 == 'yes')
  if libbzip2.found()
    conf.set('HAVE_BZIP2', 1)
  endif
else
  libbzip2 = []
endif

want_xz = get_option('xz')
if want_xz != 'no'
  libxz = dependency('liblzma',
                     required : want_xz == 'yes')
  if libxz.found()
    conf.set('HAVE_XZ', 1)
  endif
else
  libxz = []
endif

want_lz4 = get_option('lz4')
if want_lz4 != 'no'
  liblz4 = dependency('liblz4',
                      required : want_lz4 == 'yes')
  if liblz4.found()
    conf.set('HAVE_LZ4', 1)
  endif
else
  liblz4 = []
endif

libacl = cc.find_library('acl', required : false)
if libacl.found()
  conf.set('HAVE_ACL', 1)
  m4_defines += ['-DHAVE_ACL']
endif

want_libgcrypt = get_option('libgcrypt')
if want_libgcrypt != 'no'
  libgcrypt = cc.find_library('gcrypt', required : want_libgcrypt == 'yes')
  if libgcrypt.found()
    conf.set('HAVE_LIBGCRYPT', 1)
  endif
else
  libgcrypt = []
endif

want_importd = get_option('importd')
if want_importd != 'no'
  have_deps = (conf.get('HAVE_LIBCURL', 0) == 1 and
               conf.get('HAVE_ZLIB', 0) == 1 and
               conf.get('HAVE_BZIP2', 0) == 1 and
               conf.get('HAVE_XZ', 0) == 1 and
               conf.get('HAVE_LZ4', 0) == 1)
  if have_deps
    conf.set('ENABLE_IMPORTD', 1)
  elif want_importd == 'yes'
    error('importd support was requested, but dependencies are not available')
  endif
endif

want_remote = get_option('remote')
if want_remote != 'no'
  have_deps = [conf.get('HAVE_MICROHTTPD', 0) == 1,
               conf.get('HAVE_LIBCURL', 0) == 1]
  # sd-j-remote requires µhttpd, and sd-j-upload requires libcurl, so
  # it's possible to build one without the other. Complain only if
  # support was explictly requested. The auxiliary files like sysusers
  # config should be installed when any of the programs are built.
  if want_remote == 'yes' and not (have_deps[0] and have_deps[1])
    error('remote support was requested, but dependencies are not available')
  endif
  if have_deps[0] or have_deps[1]
    conf.set('ENABLE_REMOTE', 1)
  endif
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
               ]

  if get_option(pair[0])
    conf.set(pair[1], 1)
  endif
endforeach

#####################################################################

if get_option('efi')
  efi_arch = host_machine.cpu_family() # TODO: check this works at all
  if efi_arch == 'ia32'
    EFI_MACHINE_TYPE_NAME = 'ia32'
  elif efi_arch == 'x86_64'
    EFI_MACHINE_TYPE_NAME = 'x64'
  elif efi_arch == 'aarch64'
    EFI_MACHINE_TYPE_NAME = 'x64'
  else
    EFI_MACHINE_TYPE_NAME = efi_arch
  endif

  conf.set('ENABLE_EFI', 1)
  conf.set_quoted('EFI_MACHINE_TYPE_NAME', EFI_MACHINE_TYPE_NAME)
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
subdir('src/analyze')
subdir('src/coredump')
subdir('src/hostname')
subdir('src/import')
subdir('src/journal')
subdir('src/journal-remote')
subdir('src/kernel-install')
subdir('src/locale')
subdir('src/login')
subdir('src/machine')
subdir('src/nspawn')
subdir('src/resolve')
subdir('src/timedate')
subdir('src/timesync')
subdir('src/vconsole')

libjournal_core = static_library(
    'journal-core',
    libjournal_core_sources,
    journald_gperf_c,
    include_directories : includes,
    link_with : [libbasic,
                 libsystemd_internal,
                 libsystemd_journal_internal],
    install : false)

libsystemd = shared_library(
    'systemd',
    libsystemd_internal_sources,
    version : '0.18.0',
    include_directories : includes,
    link_args : ['-shared',
                 '-Wl,--version-script=' + libsystemd_sym],
    link_with : [libbasic,
                 libsystemd_internal,
                 libsystemd_journal_internal],
    dependencies : [threads],
    install : true,
    install_dir : rootlibdir)

############################################################

foreach tuple : [['myhostname', 'HAVE_MYHOSTNAME', []],
                 ['systemd',     '',               []],
                 ['mymachines', 'ENABLE_MACHINED', []],
                 ['resolve',    'ENABLE_RESOLVED', [libdl]]]

  condition = tuple[1] == '' or conf.get(tuple[1], 0) == 1
  if condition
    module = tuple[0]
    extra_deps = tuple[2]

    sym = meson.current_source_dir() + '/src/nss-@0@/nss-@0@.sym'.format(module)

    shared_library(
      'nss_' + module,
      'src/nss-@0@/nss-@0@.c'.format(module),
      version : '2',
      include_directories : includes,
      link_args : ['-shared',
                   '-Wl,--version-script=' + sym,
                   '-Wl,--undefined'],
      link_with : [libsystemd_internal,
                   libbasic],
      dependencies : [threads,
                      librt] + extra_deps,
      install : true,
      install_dir : rootlibdir)
  endif
endforeach

############################################################

subdir('src/libudev')
subdir('src/shared')
subdir('src/core')
subdir('src/udev')
subdir('src/network')

executable('systemd',
           systemd_sources,
           include_directories : includes,
           link_with : [libcore,
                        libshared],
           dependencies : [threads,
                           librt,
                           libseccomp,
                           libselinux,
                           libmount],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-analyze',
           systemd_analyze_sources,
           include_directories : includes,
           link_with : [libcore,
                        libshared],
           dependencies : [threads,
                           librt,
                           libseccomp,
                           libselinux,
                           libmount],
           install : true)

executable('systemd-journald',
           systemd_journald_sources,
           include_directories : includes,
           link_with : [libsystemd_journal_internal,
                        libjournal_core,
                        libshared,
                        libudev],
           dependencies : [threads,
                           libxz,
                           liblz4],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-cat',
           systemd_cat_sources,
           include_directories : includes,
           link_with : [libjournal_core,
                        libshared,
                        libudev],
           dependencies : [threads],
           install : true)

executable('journalctl',
           journalctl_sources,
           include_directories : includes,
           link_with : [libshared,
                        libudev],
           dependencies : [threads,
                           libqrencode,
                           libxz,
                           liblz4],
           install : true,
           install_dir : rootbindir)

executable('systemd-getty-generator',
           'src/getty-generator/getty-generator.c',
           install : true,
           install_dir : systemgeneratordir,
           include_directories : includes,
           link_with : [libshared])

executable('systemd-debug-generator',
           'src/debug-generator/debug-generator.c',
           install : true,
           install_dir : systemgeneratordir,
           include_directories : includes,
           link_with : [libshared])

executable('systemd-fstab-generator',
           'src/fstab-generator/fstab-generator.c',
           'src/core/mount-setup.c',
           install : true,
           install_dir : systemgeneratordir,
           include_directories : includes,
           link_with : [libshared])

if conf.get('ENABLE_ENVIRONMENT_D', 0) == 1
  executable('30-systemd-environment-d-generator',
             'src/environment-d-generator/environment-d-generator.c',
             install : true,
             install_dir : userenvgeneratordir,
             include_directories : includes,
             link_with : [libshared])
endif

if conf.get('ENABLE_HIBERNATE', 0) == 1
  executable('systemd-hibernate-resume-generator',
             'src/hibernate-resume/hibernate-resume-generator.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : systemgeneratordir)

  executable('systemd-hibernate-resume',
             'src/hibernate-resume/hibernate-resume.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('HAVE_BLKID', 0) == 1
  executable('systemd-gpt-auto-generator',
             'src/gpt-auto-generator/gpt-auto-generator.c',
             'src/basic/blkid-util.h',
             install : true,
             install_dir : systemgeneratordir,
             include_directories : includes,
             link_with : libshared,
             dependencies : libblkid)

  executable('systemd-dissect',
             'src/dissect/dissect.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RESOLVED', 0) == 1
  executable('systemd-resolved',
             systemd_resolved_sources,
             include_directories : includes,
             link_with : [libshared,
                         ],
             dependencies : [threads,
                             libm,
                             libidn],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-resolve',
             systemd_resolve_sources,
             include_directories : includes,
             link_with : [libshared,
                         ],
             dependencies : [threads,
                             libm,
                             libidn],
             install : true)
endif

if conf.get('ENABLE_LOGIND', 0) == 1
  executable('systemd-logind',
             systemd_logind_sources,
             include_directories : includes,
             link_with : [liblogind_core,
                          libshared],
             dependencies : [threads,
                             libacl],
             install : true,
             install_dir : rootlibexecdir)

  executable('loginctl',
             loginctl_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             liblz4,
                             libxz],
             install : true,
             install_dir : rootbindir)

  executable('systemd-inhibit',
             'src/login/inhibit.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootbindir)

  if conf.get('HAVE_PAM', 0) == 1
    shared_library(
      'pam_systemd',
      pam_systemd_c,
      name_prefix : '',
      include_directories : includes,
      link_args : ['-shared',
                   '-Wl,--version-script=' + pam_systemd_sym],
      link_with : [libshared],
      dependencies : [libpam,
                      libpam_misc],
      install : true,
      install_dir : pamlibdir)
  endif
endif

if conf.get('HAVE_PAM', 0) == 1
  executable('systemd-user-sessions',
             'src/user-sessions/user-sessions.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_EFI', 0) == 1
  executable('bootctl',
             'src/boot/bootctl.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libblkid],
             install : true)
endif

executable('systemd-socket-activate', 'src/activate/activate.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [threads],
           install : true)

executable('systemctl', 'src/systemctl/systemctl.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [threads,
                           libcap,
                           libselinux,
                           libxz,
                           liblz4],
           install : true,
           install_dir : rootbindir)

if conf.get('ENABLE_BACKLIGHT', 0) == 1
  executable('systemd-backlight',
             'src/backlight/backlight.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RFKILL', 0) == 1
  executable('systemd-rfkill',
             'src/rfkill/rfkill.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

executable('systemd-system-update-generator',
           'src/system-update-generator/system-update-generator.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : systemgeneratordir)

if conf.get('HAVE_LIBCRYPTSETUP', 0) == 1
  executable('systemd-cryptsetup',
             'src/cryptsetup/cryptsetup.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcryptsetup],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-cryptsetup-generator',
             'src/cryptsetup/cryptsetup-generator.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcryptsetup],
             install : true,
             install_dir : systemgeneratordir)

  executable('systemd-veritysetup',
             'src/veritysetup/veritysetup.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcryptsetup],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-veritysetup-generator',
             'src/veritysetup/veritysetup-generator.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcryptsetup],
             install : true,
             install_dir : systemgeneratordir)
endif

if conf.get('HAVE_SYSV_COMPAT', 0) == 1
  executable('systemd-sysv-generator',
             'src/sysv-generator/sysv-generator.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : systemgeneratordir)

  executable('systemd-rc-local-generator',
             'src/rc-local-generator/rc-local-generator.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : systemgeneratordir)
endif

if conf.get('ENABLE_HOSTNAMED', 0) == 1
  executable('systemd-hostnamed',
             'src/hostname/hostnamed.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)

  executable('hostnamectl',
             'src/hostname/hostnamectl.c',
             include_directories : includes,
             link_with : [libshared],
             install : true)
endif

if conf.get('ENABLE_LOCALED', 0) == 1
  executable('systemd-localed',
             systemd_localed_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libdl],
             install : true,
             install_dir : rootlibexecdir)

  executable('localectl',
             localectl_sources,
             include_directories : includes,
             link_with : [libshared],
             install : true)
endif

if conf.get('ENABLE_TIMEDATED', 0) == 1
  executable('systemd-timedated',
             'src/timedate/timedated.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)

  executable('timedatectl',
             'src/timedate/timedatectl.c',
             include_directories : includes,
             link_with : [libshared],
             install : true)
endif

if conf.get('ENABLE_TIMESYNCD', 0) == 1
  executable('systemd-timesyncd',
             systemd_timesyncd_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libm],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_MACHINED', 0) == 1
  executable('systemd-machined',
             systemd_machined_sources,
             include_directories : includes,
             link_with : [libmachine_core,
                          libshared],
             install : true,
             install_dir : rootlibexecdir)

  executable('machinectl',
             'src/machine/machinectl.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libxz,
                             liblz4],
             install : true,
             install_dir : rootbindir)
endif

if conf.get('ENABLE_IMPORTD', 0) == 1
  executable('systemd-importd',
             systemd_importd_sources,
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-pull',
             systemd_pull_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcurl,
                             libz,
                             libbzip2,
                             libxz,
                             libgcrypt],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-import',
             systemd_import_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcurl,
                             libz,
                             libbzip2,
                             libxz],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-export',
             systemd_export_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcurl,
                             libz,
                             libbzip2,
                             libxz],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_REMOTE', 0) == 1 and conf.get('HAVE_LIBCURL', 0) == 1
  executable('systemd-journal-upload',
             systemd_journal_upload_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libcurl,
                             libgnutls,
                             libxz,
                             liblz4],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_REMOTE', 0) == 1 and conf.get('HAVE_MICROHTTPD', 0) == 1
  executable('systemd-journal-remote',
             systemd_journal_remote_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libmicrohttpd,
                             libgnutls,
                             libxz,
                             liblz4],
             install : true,
             install_dir : rootlibexecdir)

  executable('systemd-journal-gatewayd',
             systemd_journal_gatewayd_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libmicrohttpd,
                             libgnutls,
                             libxz,
                             liblz4],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_COREDUMP', 0) == 1
  executable('systemd-coredump',
             systemd_coredump_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libacl,
                             libdw,
                             libxz,
                             liblz4],
             install : true,
             install_dir : rootlibexecdir)

  executable('coredumpctl',
             coredumpctl_sources,
             include_directories : includes,
             link_with : [libshared],
             dependencies : [threads,
                             libxz,
                             liblz4],
             install : true)
endif

if conf.get('ENABLE_BINFMT', 0) == 1
  executable('systemd-binfmt',
             'src/binfmt/binfmt.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_VCONSOLE', 0) == 1
  executable('systemd-vconsole-setup',
             'src/vconsole/vconsole-setup.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_RANDOMSEED', 0) == 1
  executable('systemd-random-seed',
             'src/random-seed/random-seed.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

if conf.get('ENABLE_FIRSTBOOT', 0) == 1
  executable('systemd-firstboot',
             'src/firstboot/firstboot.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libcrypt],
             install : true,
             install_dir : rootbindir)
endif

executable('systemd-remount-fs',
           'src/remount-fs/remount-fs.c',
           'src/core/mount-setup.c',
           'src/core/mount-setup.h',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-machine-id-setup',
           'src/machine-id-setup/machine-id-setup-main.c',
           'src/core/machine-id-setup.c',
           'src/core/machine-id-setup.h',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootbindir)

executable('systemd-fsck',
           'src/fsck/fsck.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-sleep',
           'src/sleep/sleep.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-sysctl',
           'src/sysctl/sysctl.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-ac-power',
           'src/ac-power/ac-power.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-detect-virt',
           'src/detect-virt/detect-virt.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-delta',
           'src/delta/delta.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-escape',
           'src/escape/escape.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootbindir)

executable('systemd-notify',
           'src/notify/notify.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootbindir)

executable('systemd-volatile-root',
           'src/volatile-root/volatile-root.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-cgroups-agent',
           'src/cgroups-agent/cgroups-agent.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-path',
           'src/path/path.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-ask-password',
           'src/ask-password/ask-password.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootbindir)

executable('systemd-reply-password',
           'src/reply-password/reply-password.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-tty-ask-password-agent',
           'src/tty-ask-password-agent/tty-ask-password-agent.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootbindir)

executable('systemd-cgls',
           'src/cgls/cgls.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-cgtop',
           'src/cgtop/cgtop.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-initctl',
           'src/initctl/initctl.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-mount',
           'src/mount/mount-tool.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-run',
           'src/run/run.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('systemd-stdio-bridge',
           'src/stdio-bridge/stdio-bridge.c',
           include_directories : includes,
           link_with : [libshared],
           install : true)

executable('busctl',
           'src/busctl/busctl.c',
           'src/busctl/busctl-introspect.c',
           'src/busctl/busctl-introspect.h',
           include_directories : includes,
           link_with : [libshared],
           install : true)

if conf.get('ENABLE_SYSUSERS', 0) == 1
  executable('systemd-sysusers',
             'src/sysusers/sysusers.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootbindir)
endif

if conf.get('ENABLE_TMPFILES', 0) == 1
  executable('systemd-tmpfiles',
             'src/tmpfiles/tmpfiles.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libacl],
             install : true,
             install_dir : rootbindir)
endif

if conf.get('ENABLE_HWDB', 0) == 1
  executable('systemd-hwdb',
             'src/hwdb/hwdb.c',
             'src/libsystemd/sd-hwdb/hwdb-internal.h',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootbindir)
endif

if conf.get('ENABLE_QUOTACHECK', 0) == 1
  executable('systemd-quotacheck',
             'src/quotacheck/quotacheck.c',
             include_directories : includes,
             link_with : [libshared],
             install : true,
             install_dir : rootlibexecdir)
endif

executable('systemd-socket-proxyd',
           'src/socket-proxy/socket-proxyd.c',
           include_directories : includes,
           link_with : [libshared,
                        libsystemd],
           dependencies : [threads],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-udevd',
           systemd_udevd_sources,
           include_directories : includes,
           link_with : [libudev_core,
                        libudev_internal,
                        libsystemd_network,
                        libshared],
           dependencies : [libkmod,
                           libidn,
                           libacl],
           install : true,
           install_dir : rootlibexecdir)

executable('udevadm',
           udevadm_sources,
           include_directories : includes,
           link_with : [libudev_core,
                        libudev_internal,
                        libsystemd_network,
                        libshared],
           dependencies : [libkmod,
                           libidn,
                           libacl],
           install : true,
           install_dir : rootbindir)

executable('systemd-shutdown',
           systemd_shutdown_sources,
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-update-done',
           'src/update-done/update-done.c',
           include_directories : includes,
           link_with : [libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-update-utmp',
           'src/update-utmp/update-utmp.c',
           include_directories : includes,
           link_with : [libshared],
           dependencies : [libaudit],
           install : true,
           install_dir : rootlibexecdir)

if conf.get('HAVE_KMOD', 0) == 1
  executable('systemd-modules-load',
             'src/modules-load/modules-load.c',
             include_directories : includes,
             link_with : [libshared],
             dependencies : [libkmod],
             install : true,
             install_dir : rootlibexecdir)
endif

executable('systemd-nspawn',
           systemd_nspawn_sources,
           'src/core/mount-setup.c', # FIXME: use a variable?
           'src/core/mount-setup.h',
           'src/core/loopback-setup.c',
           'src/core/loopback-setup.h',
           include_directories : [includes, include_directories('src/nspawn')],
           link_with : [libfirewall,
                        libshared],
           dependencies : [libacl,
                           libblkid,
                           libseccomp,
                           libselinux],
           install : true)

executable('systemd-networkd',
           systemd_networkd_sources,
           include_directories : includes,
           link_with : [libnetworkd_core,
                        libfirewall,
                        libsystemd_network,
                        libudev_internal,
                        libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('systemd-networkd-wait-online',
           systemd_networkd_wait_online_sources,
           include_directories : includes,
           link_with : [libnetworkd_core,
                        libshared],
           install : true,
           install_dir : rootlibexecdir)

executable('networkctl',
           networkctl_sources,
           include_directories : includes,
           link_with : [libsystemd_network,
                        libshared],
           install : true,
           install_dir : rootbindir)

executable('test-sizeof', 'src/test/test-sizeof.c',
           include_directories : includes)

make_directive_index_py = find_program('tools/make-directive-index.py')
make_man_index_py = find_program('tools/make-man-index.py')

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

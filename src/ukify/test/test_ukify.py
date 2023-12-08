#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

# pylint: disable=unused-import,import-outside-toplevel,useless-else-on-loop
# pylint: disable=consider-using-with,wrong-import-position,unspecified-encoding
# pylint: disable=protected-access,redefined-outer-name

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

try:
    import pytest
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

try:
    # pyflakes: noqa
    import pefile  # noqa
except ImportError as e:
    print(str(e), file=sys.stderr)
    sys.exit(77)

# We import ukify.py, which is a template file. But only __version__ is
# substituted, which we don't care about here. Having the .py suffix makes it
# easier to import the file.
sys.path.append(os.path.dirname(__file__) + '/..')
import ukify

build_root = os.getenv('PROJECT_BUILD_ROOT')
arg_tools = ['--tools', build_root] if build_root else []

def systemd_measure():
    opts = ukify.create_parser().parse_args(arg_tools)
    return ukify.find_tool('systemd-measure', opts=opts)

def test_guess_efi_arch():
    arch = ukify.guess_efi_arch()
    assert arch in ukify.EFI_ARCHES

def test_shell_join():
    assert ukify.shell_join(['a', 'b', ' ']) == "a b ' '"

def test_round_up():
    assert ukify.round_up(0) == 0
    assert ukify.round_up(4095) == 4096
    assert ukify.round_up(4096) == 4096
    assert ukify.round_up(4097) == 8192

def test_namespace_creation():
    ns = ukify.create_parser().parse_args(())
    assert ns.linux is None
    assert ns.initrd is None

def test_config_example():
    ex = ukify.config_example()
    assert '[UKI]' in ex
    assert 'Splash = BMP' in ex

def test_apply_config(tmp_path):
    config = tmp_path / 'config1.conf'
    config.write_text(textwrap.dedent(
        f'''
        [UKI]
        Linux = LINUX
        Initrd = initrd1 initrd2
                 initrd3
        Cmdline = 1 2 3 4 5
                  6 7 8
        OSRelease = @some/path1
        DeviceTree = some/path2
        Splash = some/path3
        Uname = 1.2.3
        EFIArch=arm
        Stub = some/path4
        PCRBanks = sha512,sha1
        SigningEngine = engine1
        SecureBootPrivateKey = some/path5
        SecureBootCertificate = some/path6
        SignKernel = no

        [PCRSignature:NAME]
        PCRPrivateKey = some/path7
        PCRPublicKey = some/path8
        Phases = {':'.join(ukify.KNOWN_PHASES)}
        '''))

    ns = ukify.create_parser().parse_args(['build'])
    ns.linux = None
    ns.initrd = []
    ukify.apply_config(ns, config)

    assert ns.linux == pathlib.Path('LINUX')
    assert ns.initrd == [pathlib.Path('initrd1'),
                         pathlib.Path('initrd2'),
                         pathlib.Path('initrd3')]
    assert ns.cmdline == '1 2 3 4 5\n6 7 8'
    assert ns.os_release == '@some/path1'
    assert ns.devicetree == pathlib.Path('some/path2')
    assert ns.splash == pathlib.Path('some/path3')
    assert ns.efi_arch == 'arm'
    assert ns.stub == pathlib.Path('some/path4')
    assert ns.pcr_banks == ['sha512', 'sha1']
    assert ns.signing_engine == 'engine1'
    assert ns.sb_key == 'some/path5'
    assert ns.sb_cert == 'some/path6'
    assert ns.sign_kernel is False

    assert ns._groups == ['NAME']
    assert ns.pcr_private_keys == [pathlib.Path('some/path7')]
    assert ns.pcr_public_keys == [pathlib.Path('some/path8')]
    assert ns.phase_path_groups == [['enter-initrd:leave-initrd:sysinit:ready:shutdown:final']]

    ukify.finalize_options(ns)

    assert ns.linux == pathlib.Path('LINUX')
    assert ns.initrd == [pathlib.Path('initrd1'),
                         pathlib.Path('initrd2'),
                         pathlib.Path('initrd3')]
    assert ns.cmdline == '1 2 3 4 5 6 7 8'
    assert ns.os_release == pathlib.Path('some/path1')
    assert ns.devicetree == pathlib.Path('some/path2')
    assert ns.splash == pathlib.Path('some/path3')
    assert ns.efi_arch == 'arm'
    assert ns.stub == pathlib.Path('some/path4')
    assert ns.pcr_banks == ['sha512', 'sha1']
    assert ns.signing_engine == 'engine1'
    assert ns.sb_key == 'some/path5'
    assert ns.sb_cert == 'some/path6'
    assert ns.sign_kernel is False

    assert ns._groups == ['NAME']
    assert ns.pcr_private_keys == [pathlib.Path('some/path7')]
    assert ns.pcr_public_keys == [pathlib.Path('some/path8')]
    assert ns.phase_path_groups == [['enter-initrd:leave-initrd:sysinit:ready:shutdown:final']]

def test_parse_args_minimal():
    with pytest.raises(ValueError):
        ukify.parse_args([])

    opts = ukify.parse_args('arg1 arg2'.split())
    assert opts.linux == pathlib.Path('arg1')
    assert opts.initrd == [pathlib.Path('arg2')]
    assert opts.os_release in (pathlib.Path('/etc/os-release'),
                               pathlib.Path('/usr/lib/os-release'))

def test_parse_args_many_deprecated():
    opts = ukify.parse_args(
        ['/ARG1', '///ARG2', '/ARG3 WITH SPACE',
         '--cmdline=a b c',
         '--os-release=K1=V1\nK2=V2',
         '--devicetree=DDDDTTTT',
         '--splash=splash',
         '--pcrpkey=PATH',
         '--uname=1.2.3',
         '--stub=STUBPATH',
         '--pcr-private-key=PKEY1',
         '--pcr-public-key=PKEY2',
         '--pcr-banks=SHA1,SHA256',
         '--signing-engine=ENGINE',
         '--secureboot-private-key=SBKEY',
         '--secureboot-certificate=SBCERT',
         '--sign-kernel',
         '--no-sign-kernel',
         '--tools=TOOLZ///',
         '--output=OUTPUT',
         '--measure',
         '--no-measure',
         ])
    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2'), pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == [pathlib.Path('PKEY1')]
    assert opts.pcr_public_keys == [pathlib.Path('PKEY2')]
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == 'SBCERT'
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False

def test_parse_args_many():
    opts = ukify.parse_args(
        ['build',
         '--linux=/ARG1',
         '--initrd=///ARG2',
         '--initrd=/ARG3 WITH SPACE',
         '--cmdline=a b c',
         '--os-release=K1=V1\nK2=V2',
         '--devicetree=DDDDTTTT',
         '--splash=splash',
         '--pcrpkey=PATH',
         '--uname=1.2.3',
         '--stub=STUBPATH',
         '--pcr-private-key=PKEY1',
         '--pcr-public-key=PKEY2',
         '--pcr-banks=SHA1,SHA256',
         '--signing-engine=ENGINE',
         '--secureboot-private-key=SBKEY',
         '--secureboot-certificate=SBCERT',
         '--sign-kernel',
         '--no-sign-kernel',
         '--tools=TOOLZ///',
         '--output=OUTPUT',
         '--measure',
         '--no-measure',
         ])
    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2'), pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == [pathlib.Path('PKEY1')]
    assert opts.pcr_public_keys == [pathlib.Path('PKEY2')]
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.sb_key == 'SBKEY'
    assert opts.sb_cert == 'SBCERT'
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is False

def test_parse_sections():
    opts = ukify.parse_args(
        ['build',
         '--linux=/ARG1',
         '--initrd=/ARG2',
         '--section=test:TESTTESTTEST',
         '--section=test2:@FILE',
         ])

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('/ARG2')]
    assert len(opts.sections) == 2

    assert opts.sections[0].name == 'test'
    assert isinstance(opts.sections[0].content, pathlib.Path)
    assert opts.sections[0].tmpfile
    assert opts.sections[0].measure is False

    assert opts.sections[1].name == 'test2'
    assert opts.sections[1].content == pathlib.Path('FILE')
    assert opts.sections[1].tmpfile is None
    assert opts.sections[1].measure is False

def test_config_priority(tmp_path):
    config = tmp_path / 'config1.conf'
    # config: use pesign and give certdir + certname
    config.write_text(textwrap.dedent(
        f'''
        [UKI]
        Linux = LINUX
        Initrd = initrd1 initrd2
                 initrd3
        Cmdline = 1 2 3 4 5
                  6 7 8
        OSRelease = @some/path1
        DeviceTree = some/path2
        Splash = some/path3
        Uname = 1.2.3
        EFIArch = arm
        Stub = some/path4
        PCRBanks = sha512,sha1
        SigningEngine = engine1
        SecureBootSigningTool = pesign
        SecureBootCertificateDir = some/path5
        SecureBootCertificateName = some/name1
        SignKernel = no

        [PCRSignature:NAME]
        PCRPrivateKey = some/path7
        PCRPublicKey = some/path8
        Phases = {':'.join(ukify.KNOWN_PHASES)}
        '''))

    # args: use sbsign and give key + cert, should override pesign
    opts = ukify.parse_args(
        ['build',
         '--linux=/ARG1',
         '--initrd=///ARG2',
         '--initrd=/ARG3 WITH SPACE',
         '--cmdline= a  b  c ',
         '--os-release=K1=V1\nK2=V2',
         '--devicetree=DDDDTTTT',
         '--splash=splash',
         '--pcrpkey=PATH',
         '--uname=1.2.3',
         '--stub=STUBPATH',
         '--pcr-private-key=PKEY1',
         '--pcr-public-key=PKEY2',
         '--pcr-banks=SHA1,SHA256',
         '--signing-engine=ENGINE',
         '--signtool=sbsign',
         '--secureboot-private-key=SBKEY',
         '--secureboot-certificate=SBCERT',
         '--sign-kernel',
         '--no-sign-kernel',
         '--tools=TOOLZ///',
         '--output=OUTPUT',
         '--measure',
         ])

    ukify.apply_config(opts, config)
    ukify.finalize_options(opts)

    assert opts.linux == pathlib.Path('/ARG1')
    assert opts.initrd == [pathlib.Path('initrd1'),
                           pathlib.Path('initrd2'),
                           pathlib.Path('initrd3'),
                           pathlib.Path('/ARG2'),
                           pathlib.Path('/ARG3 WITH SPACE')]
    assert opts.cmdline == 'a b c'
    assert opts.os_release == 'K1=V1\nK2=V2'
    assert opts.devicetree == pathlib.Path('DDDDTTTT')
    assert opts.splash == pathlib.Path('splash')
    assert opts.pcrpkey == pathlib.Path('PATH')
    assert opts.uname == '1.2.3'
    assert opts.stub == pathlib.Path('STUBPATH')
    assert opts.pcr_private_keys == [pathlib.Path('PKEY1'),
                                     pathlib.Path('some/path7')]
    assert opts.pcr_public_keys == [pathlib.Path('PKEY2'),
                                    pathlib.Path('some/path8')]
    assert opts.pcr_banks == ['SHA1', 'SHA256']
    assert opts.signing_engine == 'ENGINE'
    assert opts.signtool == 'sbsign' # from args
    assert opts.sb_key == 'SBKEY' # from args
    assert opts.sb_cert == 'SBCERT' # from args
    assert opts.sb_certdir == 'some/path5' # from config
    assert opts.sb_cert_name == 'some/name1' # from config
    assert opts.sign_kernel is False
    assert opts.tools == [pathlib.Path('TOOLZ/')]
    assert opts.output == pathlib.Path('OUTPUT')
    assert opts.measure is True

def test_help(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['--help'])
    out = capsys.readouterr()
    assert '--section' in out.out
    assert not out.err

def test_help_display(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['inspect', '--help'])
    out = capsys.readouterr()
    assert '--section' in out.out
    assert not out.err

def test_help_error_deprecated(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['a', 'b', '--no-such-option'])
    out = capsys.readouterr()
    assert not out.out
    assert '--no-such-option' in out.err
    assert len(out.err.splitlines()) == 1

def test_help_error(capsys):
    with pytest.raises(SystemExit):
        ukify.parse_args(['build', '--no-such-option'])
    out = capsys.readouterr()
    assert not out.out
    assert '--no-such-option' in out.err
    assert len(out.err.splitlines()) == 1

@pytest.fixture(scope='session')
def kernel_initrd():
    opts = ukify.create_parser().parse_args(arg_tools)
    bootctl = ukify.find_tool('bootctl', opts=opts)
    if bootctl is None:
        return None

    try:
        text = subprocess.check_output([bootctl, 'list', '--json=short'],
                                       text=True)
    except subprocess.CalledProcessError:
        return None

    items = json.loads(text)

    for item in items:
        try:
            linux = f"{item['root']}{item['linux']}"
            initrd = f"{item['root']}{item['initrd'][0].split(' ')[0]}"
        except (KeyError, IndexError):
            continue
        return ['--linux', linux, '--initrd', initrd]
    else:
        return None

def test_check_splash():
    try:
        # pyflakes: noqa
        import PIL  # noqa
    except ImportError:
        pytest.skip('PIL not available')

    with pytest.raises(OSError):
        ukify.check_splash(os.devnull)

def test_basic_operation(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmp_path}/basic.efi'
    opts = ukify.parse_args([
        'build',
        *kernel_initrd,
        f'--output={output}',
    ])
    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    subprocess.check_output(['objdump', '-h', output])

    shutil.rmtree(tmp_path)

def test_sections(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    output = f'{tmp_path}/basic.efi'
    opts = ukify.parse_args([
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=K1=V1\nK2=V2\n',
        '--section=.test:CONTENTZ',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname test'.split():
        assert re.search(fr'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    shutil.rmtree(tmp_path)

def test_addon(tmp_path):
    output = f'{tmp_path}/addon.efi'
    args = [
        'build',
        f'--output={output}',
        '--cmdline=ARG1 ARG2 ARG3',
        """--sbat=sbat,1,foo
foo,1
bar,2
""",
        '--section=.test:CONTENTZ',
        """--sbat=sbat,1,foo
baz,3
"""
    ]
    if stub := os.getenv('EFI_ADDON'):
        args += [f'--stub={stub}']
        expected_exceptions = ()
    else:
        expected_exceptions = (FileNotFoundError,)

    opts = ukify.parse_args(args)
    try:
        ukify.check_inputs(opts)
    except expected_exceptions as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text cmdline test sbat'.split():
        assert re.search(fr'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    pe = pefile.PE(output, fast_load=True)
    found = False

    for section in pe.sections:
        if section.Name.rstrip(b"\x00").decode() == ".sbat":
            assert found is False
            split = section.get_data().rstrip(b"\x00").decode().splitlines()
            assert split == ["sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md", "foo,1", "bar,2", "baz,3"]
            found = True

    assert found is True


def unbase64(filename):
    tmp = tempfile.NamedTemporaryFile()
    base64.decode(filename.open('rb'), tmp)
    tmp.flush()
    return tmp


def test_uname_scraping(kernel_initrd):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')

    assert kernel_initrd[0] == '--linux'
    uname = ukify.Uname.scrape(kernel_initrd[1])
    assert re.match(r'\d+\.\d+\.\d+', uname)

@pytest.mark.parametrize("days", [365*10, None])
def test_efi_signing_sbsign(days, kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('sbsign'):
        pytest.skip('sbsign not found')

    ourdir = pathlib.Path(__file__).parent
    cert = unbase64(ourdir / 'example.signing.crt.base64')
    key = unbase64(ourdir / 'example.signing.key.base64')

    output = f'{tmp_path}/signed.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        f'--secureboot-certificate={cert.name}',
        f'--secureboot-private-key={key.name}',
    ]
    if days is not None:
        args += [f'--secureboot-certificate-validity={days}']

    opts = ukify.parse_args(args)

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    if shutil.which('sbverify'):
        # let's check that sbverify likes the resulting file
        dump = subprocess.check_output([
            'sbverify',
            '--cert', cert.name,
            output,
        ], text=True)

        assert 'Signature verification OK' in dump

    shutil.rmtree(tmp_path)

def test_efi_signing_pesign(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('pesign'):
        pytest.skip('pesign not found')

    nss_db = f'{tmp_path}/nss_db'
    name = 'Test_Secureboot'
    author = 'systemd'

    subprocess.check_call(['mkdir', '-p', nss_db])
    cmd = f'certutil -N --empty-password -d {nss_db}'.split(' ')
    subprocess.check_call(cmd)
    cmd = f'efikeygen -d {nss_db} -S -k -c CN={author} -n {name}'.split(' ')
    subprocess.check_call(cmd)

    output = f'{tmp_path}/signed.efi'
    opts = ukify.parse_args([
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--signtool=pesign',
        '--cmdline=ARG1 ARG2 ARG3',
        f'--secureboot-certificate-name={name}',
        f'--secureboot-certificate-dir={nss_db}',
    ])

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that sbverify likes the resulting file
    dump = subprocess.check_output([
        'pesign', '-S',
        '-i', output,
    ], text=True)

    assert f"The signer's common name is {author}" in dump

    shutil.rmtree(tmp_path)

def test_inspect(kernel_initrd, tmp_path, capsys):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if not shutil.which('sbsign'):
        pytest.skip('sbsign not found')

    ourdir = pathlib.Path(__file__).parent
    cert = unbase64(ourdir / 'example.signing.crt.base64')
    key = unbase64(ourdir / 'example.signing.key.base64')

    output = f'{tmp_path}/signed2.efi'
    uname_arg='1.2.3'
    osrel_arg='Linux'
    cmdline_arg='ARG1 ARG2 ARG3'
    opts = ukify.parse_args([
        'build',
        *kernel_initrd,
        f'--cmdline={cmdline_arg}',
        f'--os-release={osrel_arg}',
        f'--uname={uname_arg}',
        f'--output={output}',
        f'--secureboot-certificate={cert.name}',
        f'--secureboot-private-key={key.name}',
    ])

    ukify.check_inputs(opts)
    ukify.make_uki(opts)

    opts = ukify.parse_args(['inspect', output])
    ukify.inspect_sections(opts)

    text = capsys.readouterr().out

    expected_osrel = f'.osrel:\n  size: {len(osrel_arg)}'
    assert expected_osrel in text
    expected_cmdline = f'.cmdline:\n  size: {len(cmdline_arg)}'
    assert expected_cmdline in text
    expected_uname = f'.uname:\n  size: {len(uname_arg)}'
    assert expected_uname in text

    expected_initrd = '.initrd:\n  size:'
    assert expected_initrd in text
    expected_linux = '.linux:\n  size:'
    assert expected_linux in text

    shutil.rmtree(tmp_path)

def test_pcr_signing(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if systemd_measure() is None:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')

    output = f'{tmp_path}/signed.efi'
    args = [
        'build',
        *kernel_initrd,
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha1',   # use sha1 because it doesn't really matter
        f'--pcr-private-key={priv.name}',
    ] + arg_tools

    # If the public key is not explicitly specified, it is derived automatically. Let's make sure everything
    # works as expected both when the public keys is specified explicitly and when it is derived from the
    # private key.
    for extra in ([f'--pcrpkey={pub.name}', f'--pcr-public-key={pub.name}'], []):
        opts = ukify.parse_args(args + extra)
        try:
            ukify.check_inputs(opts)
        except OSError as e:
            pytest.skip(str(e))

        ukify.make_uki(opts)

        # let's check that objdump likes the resulting file
        dump = subprocess.check_output(['objdump', '-h', output], text=True)

        for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
            assert re.search(fr'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

        # objcopy fails when called without an output argument (EPERM).
        # It also fails when called with /dev/null (file truncated).
        # It also fails when called with /dev/zero (because it reads the
        # output file, infinitely in this case.)
        # So let's just call it with a dummy output argument.
        subprocess.check_call([
            'objcopy',
            *(f'--dump-section=.{n}={tmp_path}/out.{n}' for n in (
                'pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline')),
            output,
            tmp_path / 'dummy',
        ],
            text=True)

        assert open(tmp_path / 'out.pcrpkey').read() == open(pub.name).read()
        assert open(tmp_path / 'out.osrel').read() == 'ID=foobar\n'
        assert open(tmp_path / 'out.uname').read() == '1.2.3'
        assert open(tmp_path / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
        sig = open(tmp_path / 'out.pcrsig').read()
        sig = json.loads(sig)
        assert list(sig.keys()) == ['sha1']
        assert len(sig['sha1']) == 4   # four items for four phases

    shutil.rmtree(tmp_path)

def test_pcr_signing2(kernel_initrd, tmp_path):
    if kernel_initrd is None:
        pytest.skip('linux+initrd not found')
    if systemd_measure() is None:
        pytest.skip('systemd-measure not found')

    ourdir = pathlib.Path(__file__).parent
    pub = unbase64(ourdir / 'example.tpm2-pcr-public.pem.base64')
    priv = unbase64(ourdir / 'example.tpm2-pcr-private.pem.base64')
    pub2 = unbase64(ourdir / 'example.tpm2-pcr-public2.pem.base64')
    priv2 = unbase64(ourdir / 'example.tpm2-pcr-private2.pem.base64')

    # simulate a microcode file
    with open(f'{tmp_path}/microcode', 'wb') as microcode:
        microcode.write(b'1234567890')

    output = f'{tmp_path}/signed.efi'
    assert kernel_initrd[0] == '--linux'
    opts = ukify.parse_args([
        'build',
        *kernel_initrd[:2],
        f'--initrd={microcode.name}',
        *kernel_initrd[2:],
        f'--output={output}',
        '--uname=1.2.3',
        '--cmdline=ARG1 ARG2 ARG3',
        '--os-release=ID=foobar\n',
        '--pcr-banks=sha1',
        f'--pcrpkey={pub2.name}',
        f'--pcr-public-key={pub.name}',
        f'--pcr-private-key={priv.name}',
        '--phases=enter-initrd enter-initrd:leave-initrd',
        f'--pcr-public-key={pub2.name}',
        f'--pcr-private-key={priv2.name}',
        '--phases=sysinit ready shutdown final',  # yes, those phase paths are not reachable
    ] + arg_tools)

    try:
        ukify.check_inputs(opts)
    except OSError as e:
        pytest.skip(str(e))

    ukify.make_uki(opts)

    # let's check that objdump likes the resulting file
    dump = subprocess.check_output(['objdump', '-h', output], text=True)

    for sect in 'text osrel cmdline linux initrd uname pcrsig'.split():
        assert re.search(fr'^\s*\d+\s+\.{sect}\s+[0-9a-f]+', dump, re.MULTILINE)

    subprocess.check_call([
        'objcopy',
        *(f'--dump-section=.{n}={tmp_path}/out.{n}' for n in (
            'pcrpkey', 'pcrsig', 'osrel', 'uname', 'cmdline', 'initrd')),
        output,
        tmp_path / 'dummy',
    ],
        text=True)

    assert open(tmp_path / 'out.pcrpkey').read() == open(pub2.name).read()
    assert open(tmp_path / 'out.osrel').read() == 'ID=foobar\n'
    assert open(tmp_path / 'out.uname').read() == '1.2.3'
    assert open(tmp_path / 'out.cmdline').read() == 'ARG1 ARG2 ARG3'
    assert open(tmp_path / 'out.initrd', 'rb').read(10) == b'1234567890'

    sig = open(tmp_path / 'out.pcrsig').read()
    sig = json.loads(sig)
    assert list(sig.keys()) == ['sha1']
    assert len(sig['sha1']) == 6   # six items for six phases paths

    shutil.rmtree(tmp_path)

def test_key_cert_generation(tmp_path):
    opts = ukify.parse_args([
        'genkey',
        f"--pcr-public-key={tmp_path / 'pcr1.pub.pem'}",
        f"--pcr-private-key={tmp_path / 'pcr1.priv.pem'}",
        '--phases=enter-initrd enter-initrd:leave-initrd',
        f"--pcr-public-key={tmp_path / 'pcr2.pub.pem'}",
        f"--pcr-private-key={tmp_path / 'pcr2.priv.pem'}",
        '--phases=sysinit ready',
        f"--secureboot-private-key={tmp_path / 'sb.priv.pem'}",
        f"--secureboot-certificate={tmp_path / 'sb.cert.pem'}",
    ])
    assert opts.verb == 'genkey'
    ukify.check_cert_and_keys_nonexistent(opts)

    pytest.importorskip('cryptography')

    ukify.generate_keys(opts)

    if not shutil.which('openssl'):
        return

    for key in (tmp_path / 'pcr1.priv.pem',
                tmp_path / 'pcr2.priv.pem',
                tmp_path / 'sb.priv.pem'):
        out = subprocess.check_output([
            'openssl', 'rsa',
            '-in', key,
            '-text',
            '-noout',
        ], text = True)
        assert 'Private-Key' in out
        assert '2048 bit' in out

    for pub in (tmp_path / 'pcr1.pub.pem',
                tmp_path / 'pcr2.pub.pem'):
        out = subprocess.check_output([
            'openssl', 'rsa',
            '-pubin',
            '-in', pub,
            '-text',
            '-noout',
        ], text = True)
        assert 'Public-Key' in out
        assert '2048 bit' in out

    out = subprocess.check_output([
        'openssl', 'x509',
        '-in', tmp_path / 'sb.cert.pem',
        '-text',
        '-noout',
    ], text = True)
    assert 'Certificate' in out
    assert 'Issuer: CN = SecureBoot signing key on host' in out

if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv))

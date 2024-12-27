---
title: Credentials
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# System and Service Credentials

The `systemd` service manager supports a "credential" concept for securely
acquiring and passing credential data to systems and services. The precise
nature of the credential data is up to applications, but the concept is
intended to provide systems and services with potentially security sensitive
cryptographic keys, certificates, passwords, identity information and similar
types of information. It may also be used as generic infrastructure for
parameterizing systems and services.

Traditionally, data of this nature has often been provided to services via
environment variables (which is problematic because by default they are
inherited down the process tree, have size limitations, and issues with binary
data) or simple, unencrypted files on disk. `systemd`'s system and service
credentials are supposed to provide a better alternative for this
purpose. Specifically, the following features are provided:

1. Service credentials are acquired at the moment of service activation, and
   released on service deactivation. They are immutable during the service
   runtime.

2. Service credentials are accessible to service code as regular files, the
   path to access them is derived from the environment variable
   `$CREDENTIALS_DIRECTORY`.

3. Access to credentials is restricted to the service's user. Unlike
   environment variables the credential data is not propagated down the process
   tree. Instead each time a credential is accessed an access check is enforced
   by the kernel. If the service is using file system namespacing the loaded
   credential data is invisible to all other services.

4. Service credentials may be acquired from files on disk, specified as literal
   strings in unit files, acquired from another service dynamically via an
   `AF_UNIX` socket, or inherited from the system credentials the system itself
   received.

5. Credentials may optionally be encrypted and authenticated, either with a key
   derived from a local TPM2 chip, or one stored in `/var/`, or both. This
   encryption is supposed to *just* *work*, and requires no manual setup. (That
   is besides first encrypting relevant credentials with one simple command,
   see below.)

6. Service credentials are placed in non-swappable memory. (If permissions
   allow it, via `ramfs`.)

7. Credentials may be acquired from a hosting VM hypervisor (SMBIOS OEM strings
   or qemu `fw_cfg`), a hosting container manager, the kernel command line,
   from the initrd, or from the UEFI environment via the EFI System Partition
   (via `systemd-stub`). Such system credentials may then be propagated into
   individual services as needed.

8. Credentials are an effective way to pass parameters into services that run
   with `RootImage=` or `RootDirectory=` and thus cannot read these resources
   directly from the host directory tree.
   Specifically, [Portable Services](/PORTABLE_SERVICES) may be
   parameterized this way securely and robustly.

9. Credentials can be binary and relatively large (though currently an overall
   size limit of 1M per service is enforced).

## Configuring per-Service Credentials

Within unit files, there are the following settings to configure service 
credentials.

1. `LoadCredential=` may be used to load a credential from disk, from an
   `AF_UNIX` socket, or propagate them from a system credential.

2. `ImportCredential=` may be used to load one or more (optionally encrypted)
   credentials from disk or from the credential stores.

3. `SetCredential=` may be used to set a credential to a literal string encoded
   in the unit file. Because unit files are world-readable (both on disk and
   via D-Bus), this should only be used for credentials that aren't sensitive,
   e.g. public keys or certificates, but not private keys.

4. `LoadCredentialEncrypted=` is similar to `LoadCredential=` but will load an
   encrypted credential, and decrypt it before passing it to the service. For
   details on credential encryption, see below.

5. `SetCredentialEncrypted=` is similar to `SetCredential=` but expects an
   encrypted credential to be specified literally. Unlike `SetCredential=` it
   is thus safe to be used even for sensitive information, because even though
   unit files are world readable, the ciphertext included in them cannot be
   decoded unless access to TPM2/encryption key is available.

Each credential configured with these options carries a short name (suitable
for inclusion in a filename) in the unit file, under which the invoked service
code can then retrieve it. Each name should only be specified once.

For details about these settings [see the man
page](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Credentials).

It is a good idea to also enable mount namespacing for services that process
credentials configured this way. If so, the runtime credential directory of the
specific service is not visible to any other service. Use `PrivateMounts=` as
minimal option to enable such namespacing. Note that many other sandboxing
settings (e.g. `ProtectSystem=`, `ReadOnlyPaths=` and similar) imply
`PrivateMounts=`, hence oftentimes it's not necessary to set this option
explicitly.

## Programming Interface from Service Code

When a service is invoked with one or more credentials set it will have an
environment variable `$CREDENTIALS_DIRECTORY` set. It contains an absolute path
to a directory the credentials are placed in. In this directory for each
configured credential one file is placed. In addition to the
`$CREDENTIALS_DIRECTORY` environment variable passed to the service processes
the `%d` specifier in unit files resolves to the service's credential
directory.

Example unit file:

```
…
[Service]
ExecStart=/usr/bin/myservice.sh
LoadCredential=foobar:/etc/myfoobarcredential.txt
Environment=FOOBARPATH=%d/foobar
…
```

Associated service shell script `/usr/bin/myservice.sh`:

```sh
#!/bin/sh

sha256sum $CREDENTIALS_DIRECTORY/foobar
sha256sum $FOOBARPATH

```

A service defined like this will get the contents of the file
`/etc/myfoobarcredential.txt` passed as credential `foobar`, which is hence
accessible under `$CREDENTIALS_DIRECTORY/foobar`. Since we additionally pass
the path to it as environment variable `$FOOBARPATH` the credential is also
accessible as the path in that environment variable. When invoked, the service
will hence show the same SHA256 hash value of `/etc/myfoobarcredential.txt`
twice.

In an ideal world, well-behaved service code would directly support credentials
passed this way, i.e. look for `$CREDENTIALS_DIRECTORY` and load the credential
data it needs from there. For daemons that do not support this but allow
passing credentials via a path supplied over the command line use
`${CREDENTIALS_DIRECTORY}` in the `ExecStart=` command line to reference the
credentials directory. For daemons that allow passing credentials via a path
supplied as environment variable, use the `%d` specifier in the `Environment=`
setting to build valid paths to specific credentials.

Encrypted credentials are automatically decrypted/authenticated during service
activation, so that service code only receives plaintext credentials.

## Programming Interface from Generator Code

[Generators](https://www.freedesktop.org/software/systemd/man/systemd.generator.html)
may generate native unit files from external configuration or system
parameters, such as system credentials. Note that they run outside of service
context, and hence will not receive encrypted credentials in plaintext
form. Specifically, credentials passed into the system in encrypted form will
be placed as they are in a directory referenced by the
`$ENCRYPTED_CREDENTIALS_DIRECTORY` environment variable, and those passed in
plaintext form will be placed in `$CREDENTIALS_DIRECTORY`. Use a command such
as `systemd-creds --system cat …` to access both forms of credentials, and
decrypt them if needed (see
[systemd-creds(1)](https://www.freedesktop.org/software/systemd/man/systemd-creds.html)
for details.

Note that generators typically run very early during boot (similar to initrd
code), earlier than the `/var/` file system is necessarily mounted (which is
where the system's credential encryption secret is located). Thus it's a good
idea to encrypt credentials with `systemd-creds encrypt --with-key=auto-initrd`
if they shall be consumed by a generator, to ensure they are locked to the TPM2
only, not the credentials secret stored below `/var/`.

For further details about encrypted credentials, see below.

## Tools

The
[`systemd-creds`](https://www.freedesktop.org/software/systemd/man/systemd-creds.html)
tool is provided to work with system and service credentials. It may be used to
access and enumerate system and service credentials, or to encrypt/decrypt credentials
(for details about the latter, see below).

When invoked from service context, `systemd-creds` passed without further
parameters will list passed credentials. The `systemd-creds cat xyz` command
may be used to write the contents of credential `xyz` to standard output. If
these calls are combined with the `--system` switch credentials passed to the
system as a whole are shown, instead of those passed to the service the
command is invoked from.

Example use:

```sh
systemd-run -P --wait -p LoadCredential=abc:/etc/hosts systemd-creds cat abc
```

This will invoke a transient service with a credential `abc` sourced from the
system's `/etc/hosts` file. This credential is then written to standard output
via `systemd-creds cat`.

## Encryption

Credentials are supposed to be useful for carrying sensitive information, such
as cryptographic key material. For such purposes (symmetric) encryption and
authentication are provided to make storage of the data at rest safer. The data
may be encrypted and authenticated with AES256-GCM. The encryption key can
either be one derived from the local TPM2 device, or one stored in
`/var/lib/systemd/credential.secret`, or a combination of both. If a TPM2
device is available and `/var/` resides on a persistent storage, the default
behaviour is to use the combination of both for encryption, thus ensuring that
credentials protected this way can only be decrypted and validated on the
local hardware and OS installation. Encrypted credentials stored on disk thus
cannot be decrypted without access to the TPM2 chip and the aforementioned key
file `/var/lib/systemd/credential.secret`. Moreover, credentials cannot be
prepared on a machine other than the local one.

Decryption generally takes place at the moment of service activation. This
means credentials passed to the system can be either encrypted or plaintext and
remain that way all the way while they are propagated to their consumers, until
the moment of service activation when they are decrypted and authenticated, so
that the service only sees plaintext credentials.

The `systemd-creds` tool provides the commands `encrypt` and `decrypt` to
encrypt and decrypt/authenticate credentials. Example:

```sh
systemd-creds encrypt --name=foobar plaintext.txt ciphertext.cred
shred -u plaintext.txt
systemd-run -P --wait -p LoadCredentialEncrypted=foobar:$(pwd)/ciphertext.cred systemd-creds cat foobar
```

This will first create an encrypted copy of the file `plaintext.txt` in the
encrypted credential file `ciphertext.cred`. It then securely removes the
source file. It then runs a transient service, that reads the encrypted file
and passes it as decrypted credential `foobar` to the invoked service binary
(which here is the `systemd-creds` tool, which just writes the data
it received to standard output).

Instead of storing the encrypted credential as a separate file on disk, it can
also be embedded in the unit file. Example:

```
systemd-creds encrypt -p --name=foobar plaintext.txt -
```

This will output a `SetCredentialEncrypted=` line that can directly be used in
a unit file. e.g.:

```
…
[Service]
ExecStart=/usr/bin/systemd-creds cat foobar
SetCredentialEncrypted=foobar: \
        k6iUCUh0RJCQyvL8k8q1UyAAAAABAAAADAAAABAAAAC1lFmbWAqWZ8dCCQkAAAAAgAAAA \
        AAAAAALACMA0AAAACAAAAAAfgAg9uNpGmj8LL2nHE0ixcycvM3XkpOCaf+9rwGscwmqRJ \
        cAEO24kB08FMtd/hfkZBX8PqoHd/yPTzRxJQBoBsvo9VqolKdy9Wkvih0HQnQ6NkTKEdP \
        HQ08+x8sv5sr+Mkv4ubp3YT1Jvv7CIPCbNhFtag1n5y9J7bTOKt2SQwBOAAgACwAAABIA \
        ID8H3RbsT7rIBH02CIgm/Gv1ukSXO3DMHmVQkDG0wEciABAAII6LvrmL60uEZcp5qnEkx \
        SuhUjsDoXrJs0rfSWX4QAx5PwfdFuxPusgEfTYIiCb8a/W6RJc7cMweZVCQMbTARyIAAA \
        AAJt7Q9F/Gz0pBv1Lc4Dpn1WpebyBBm+vQ5N/lSKW2XSm8cONwCopxpDc7wJjXg7OTR6r \
        xGCpIvGXLt3ibwJl81woLya2RRjIvc/R2zNm/yWzZAjiOLPih4SuHthqiX98ey8PUmZJB \
        VGXglCZFjBx+d7eCqTIdghtp5pkDGwMJT6pjw4FfyFK2nJPawFKPAqzw9DK2iYttFeXi5 \
        19xCfLBH9NKS/idlYXrhp+XIEtsr26s4lx5y10Goyc3qDOR3RD2cuZj0gHwV35hhhhcCz \
        JaYytef1X/YL+7fYH5kuE4rxSksoUuA/LhtjszBeGbcbIT+O8SuvBJHLKTSHxPL8FTyk3 \
        L4FSkEHs0rYwUIkKmnGohDdsYrMJ2fjH3yDNBP16aD1+f/Nuh75cjhUnGsDLt9K4hGg== \
…
```

## Inheritance from Container Managers, Hypervisors, Kernel Command Line, or the UEFI Boot Environment

Sometimes it is useful to parameterize whole systems the same way as services,
via `systemd` credentials. In particular, it might make sense to boot a
system with a set of credentials that are then propagated to individual
services where they are ultimately consumed.

`systemd` supports five ways to pass credentials to systems:

1. A container manager may set the `$CREDENTIALS_DIRECTORY` environment
   variable for systemd running as PID 1 in the container, the same way as
   systemd would set it for a service it invokes.
   [`systemd-nspawn(1)`](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#Credentials)'s
   `--set-credential=` and `--load-credential=` switches implement this, in
   order to pass arbitrary credentials from host to container payload. Also see
   the [Container Interface](/CONTAINER_INTERFACE) documentation.

2. Quite similar, VMs can be passed credentials via SMBIOS OEM strings (example
   qemu command line switch `-smbios
   type=11,value=io.systemd.credential:foo=bar` or `-smbios
   type=11,value=io.systemd.credential.binary:foo=YmFyCg==`, the latter taking
   a Base64 encoded argument to permit binary credentials being passed
   in). Alternatively, qemu VMs can be invoked with `-fw_cfg
   name=opt/io.systemd.credentials/foo,string=bar` to pass credentials from
   host through the hypervisor into the VM via qemu's `fw_cfg` mechanism. (All
   three of these specific switches would set credential `foo` to `bar`.)
   Passing credentials via the SMBIOS mechanism is typically preferable over
   `fw_cfg` since it is faster and less specific to the chosen VMM implementation.
   Moreover, `fw_cfg` has a 55 character limitation on names passed that way. So some settings may not fit.

3. Credentials may be passed from the initrd to the host during the initrd → host transition.
   Provisioning systems that run in the initrd may use this to install credentials on the system.
   All files placed in `/run/credentials/@initrd/` are imported into the set of file system credentials during the transition.
   The files (and their directory) are removed once this is completed.

4. Credentials may also be passed from the UEFI environment to userspace, if
   the
   [`systemd-stub`](https://www.freedesktop.org/software/systemd/man/systemd-stub.html)
   UEFI kernel stub is used.
   This allows placing encrypted credentials in the EFI System Partition, which are then picked up by `systemd-stub` and passed to the kernel and ultimately userspace where systemd receives them.
   This is useful to implement secure parameterization of vendor-built and signed
   initrds, as userspace can place credentials next to these EFI kernels, and
   be sure they can be accessed securely from initrd context.

5. Credentials can also be passed into a system via the kernel command line,
   via the `systemd.set_credential=` and `systemd.set_credential_binary=`
   kernel command line options (the latter takes Base64 encoded binary data).
   Note though that any data specified here is visible to all userspace
   applications (even unprivileged ones) via `/proc/cmdline`. Typically, this
   is hence not useful to pass sensitive information, and should be avoided.

Credentials passed to the system may be enumerated/displayed via `systemd-creds
--system`. They may also be propagated down to services, via the
`LoadCredential=` setting. Example:

```
systemd-nspawn --set-credential=mycred:supersecret -i test.raw -b
```

or

```
qemu-system-x86_64 \
        -machine type=q35,accel=kvm,smm=on \
        -smp 2 \
        -m 1G \
        -cpu host \
        -nographic \
        -nodefaults \
        -serial mon:stdio \
        -drive if=none,id=hd,file=test.raw,format=raw \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,drive=hd,bootindex=1 \
        -smbios type=11,value=io.systemd.credential:mycred=supersecret
```

Either of these lines will boot a disk image `test.raw`, once as container via
`systemd-nspawn`, and once as VM via `qemu`. In each case the credential
`mycred` is set to `supersecret`.

Inside of the system invoked that way the credential may then be viewed:

```sh
systemd-creds --system cat mycred
```

Or propagated to services further down:

```
systemd-run -p ImportCredential=mycred -P --wait systemd-creds cat mycred
```

## Well-Known Credentials

Various services shipped with `systemd` consume credentials for tweaking behaviour:

* [`systemd(1)`](https://www.freedesktop.org/software/systemd/man/systemd.html)
  (I.E.: PID1, the system manager) will look for the credential `vmm.notify_socket`
  and will use it to send a `READY=1` datagram when the system has finished
  booting.
  This is useful for hypervisors/VMMs or other processes on the host to receive a notification via VSOCK when a virtual machine has finished booting.
  Note that in case the hypervisor does not support `SOCK_DGRAM` over `AF_VSOCK`,
  `SOCK_SEQPACKET` will be tried instead.
  The credential payload should be in the form: `vsock:<CID>:<PORT>`.
  Also note that this requires support for VSOCK to be built in both the guest and the host kernels, and the kernel modules to be loaded.

* [`systemd-sysusers(8)`](https://www.freedesktop.org/software/systemd/man/systemd-sysusers.html)
  will look for the credentials `passwd.hashed-password.<username>`,
  `passwd.plaintext-password.<username>` and `passwd.shell.<username>` to
  configure the password (either in UNIX hashed form, or plaintext) or shell of
  system users created.
  Replace `<username>` with the system user of your choice, for example, `root`.

* [`systemd-firstboot(1)`](https://www.freedesktop.org/software/systemd/man/systemd-firstboot.html)
  will look for the credentials `firstboot.locale`, `firstboot.locale-messages`,
  `firstboot.keymap`, `firstboot.timezone`, that configure locale, keymap or
  timezone settings in case the data is not yet set in `/etc/`.

* [`tmpfiles.d(5)`](https://www.freedesktop.org/software/systemd/man/tmpfiles.d.html)
  will look for the credentials `tmpfiles.extra` with arbitrary tmpfiles.d lines.
  Can be encoded in base64 to allow easily passing it on the command line.

* Further well-known credentials are documented in
  [`systemd.system-credentials(7)`](https://www.freedesktop.org/software/systemd/man/systemd.system-credentials.html).

In future more services are likely to gain support for consuming credentials.

Example:

```
systemd-nspawn -i test.raw  \
        --set-credential=passwd.hashed-password.root:$(mkpasswd mysecret) \
        --set-credential=firstboot.locale:C.UTF-8 \
        -b
```

This boots the specified disk image as `systemd-nspawn` container, and passes
the root password `mysecret`and default locale `C.UTF-8` to use to it. This
data is then propagated by default to `systemd-sysusers.service` and
`systemd-firstboot.service`, where it is applied. (Note that these services
will only do so if these settings in `/etc/` are so far unset, i.e. they only
have an effect on *unprovisioned* systems, and will never override data already
established in `/etc/`.) A similar line for qemu is:

```
qemu-system-x86_64 \
        -machine type=q35,accel=kvm,smm=on \
        -smp 2 \
        -m 1G \
        -cpu host \
        -nographic \
        -nodefaults \
        -serial mon:stdio \
        -drive if=none,id=hd,file=test.raw,format=raw \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,drive=hd,bootindex=1 \
        -smbios type=11,value=io.systemd.credential:passwd.hashed-password.root=$(mkpasswd mysecret) \
        -smbios type=11,value=io.systemd.credential:firstboot.locale=C.UTF-8
```

This boots the specified disk image via qemu, provisioning public key SSH access
for the root user from the caller's key, and sends a notification when booting
has finished to a process on the host:

```
qemu-system-x86_64 \
        -machine type=q35,accel=kvm,smm=on \
        -smp 2 \
        -m 1G \
        -cpu host \
        -nographic \
        -nodefaults \
        -serial mon:stdio \
        -drive if=none,id=hd,file=test.raw,format=raw \
        -device virtio-scsi-pci,id=scsi \
        -device scsi-hd,drive=hd,bootindex=1 \
        -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=42 \
        -smbios type=11,value=io.systemd.credential:vmm.notify_socket=vsock:2:1234 \
        -smbios type=11,value=io.systemd.credential.binary:tmpfiles.extra=$(echo -e "d /root/.ssh 0750 root root -\nf~ /root/.ssh/authorized_keys 0600 root root - $(ssh-add -L | base64 -w 0)" | base64 -w 0)
```

A process on the host can listen for the notification, for example:

```
$ socat - VSOCK-LISTEN:1234,socktype=5
READY=1
```

## Relevant Paths

From *service* perspective the runtime path to find loaded credentials in is
provided in the `$CREDENTIALS_DIRECTORY` environment variable. For *system
services* the credential directory will be `/run/credentials/<unit name>`, but
hardcoding this path is discouraged, because it does not work for *user
services*. Packagers and system administrators may hardcode the credential path
as a last resort for software that does not yet search for credentials relative
to `$CREDENTIALS_DIRECTORY`.

From *generator* perspective the runtime path to find credentials passed into
the system in plaintext form in is provided in `$CREDENTIALS_DIRECTORY`, and
those passed into the system in encrypted form is provided in
`$ENCRYPTED_CREDENTIALS_DIRECTORY`.

At runtime, credentials passed to the *system* are placed in
`/run/credentials/@system/` (for regular credentials, such as those passed from
a container manager or via qemu) and `/run/credentials/@encrypted/` (for
credentials that must be decrypted/validated before use, such as those from
`systemd-stub`).

The `ImportCredential=` setting (and the `LoadCredential=` and
`LoadCredentialEncrypted=` settings when configured with a relative source
path) will search for the source file to read the credential from automatically.
Primarily, these credentials are searched among the credentials passed into the system. If not found there, they are searched in `/etc/credstore/`, `/run/credstore/`, `/usr/lib/credstore/`. `LoadCredentialEncrypted=` will also search
`/etc/credstore.encrypted/` and similar directories.
`ImportCredential=` will search both the non-encrypted and encrypted directories.
These directories are hence a great place to store credentials to load on the system.

## Conditionalizing Services

Sometimes it makes sense to conditionalize system services and invoke them only
if the right system credential is passed to the system.
Use the `ConditionCredential=` and `AssertCredential=` unit file settings for that.

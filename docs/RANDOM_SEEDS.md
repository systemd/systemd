---
title: Random Seeds
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Random Seeds

systemd can help in a number of ways with providing reliable, high quality
random numbers from early boot on.

## Linux Kernel Entropy Pool

Today's computer systems require random number generators for numerous cryptographic and other purposes.
On Linux systems, the kernel's entropy pool is typically used as high-quality source of random numbers. The kernel's entropy pool combines various entropy inputs together, mixes them and provides
an API to userspace as well as to internal kernel subsystems to retrieve it.

This entropy pool needs to be initialized with a minimal level of entropy
before it can provide high quality, cryptographic random numbers to applications.
Until the entropy pool is fully initialized application requests for high-quality random numbers cannot be fulfilled.

The Linux kernel provides three relevant userspace APIs to request random data
from the kernel's entropy pool:

* The [`getrandom()`](https://man7.org/linux/man-pages/man2/getrandom.2.html)
  system call with its `flags` parameter set to 0.
  If invoked, the calling program will synchronously block until the random pool is fully initialized
  and the requested bytes can be provided.

* The `getrandom()` system call with its `flags` parameter set to `GRND_NONBLOCK`.
  If invoked, the request for random bytes will fail if the pool is not initialized yet.

* Reading from the
  [`/dev/urandom`](https://man7.org/linux/man-pages/man4/urandom.4.html)
  pseudo-device will always return random bytes immediately, even if the pool is not initialized.
  The provided random bytes will be of low quality in this case however.
  Moreover, the kernel will log about all programs using this interface in this state, and which thus potentially rely on an uninitialized entropy pool.

(Strictly speaking, there are more APIs, for example `/dev/random`, but these
should not be used by almost any application and hence aren't mentioned here.)

Note that the time it takes to initialize the random pool may differ between systems.
If local hardware random number generators are available, initialization is likely quick, but particularly in embedded and virtualized environments available entropy is small and thus random pool initialization
might take a long time (up to tens of minutes!).

Modern hardware tends to come with a number of hardware random number generators (hwrng), that may be used to relatively quickly fill up the entropy pool.
Specifically:

* All recent Intel and AMD CPUs provide the CPU opcode
  [RDRAND](https://en.wikipedia.org/wiki/RdRand) to acquire random bytes.
  Linux includes random bytes generated this way in its entropy pool, but didn't use
  to credit entropy for it (i.e. data from this source wasn't considered good
  enough to consider the entropy pool properly filled even though it was used).
  This has changed recently however, and most big distributions have
  turned on the `CONFIG_RANDOM_TRUST_CPU=y` kernel compile time option.
  This means systems with CPUs supporting this opcode will be able to very quickly
  reach the "pool filled" state.

* The TPM security chip that is available on all modern desktop systems has a hwrng.
  It is also fed into the entropy pool, but generally not credited entropy.
  You may use `rng_core.default_quality=1000` on the kernel command line to change that,
  but note that this is a global setting affect all hwrngs.
  (Yeah, that's weird.)

* Many Intel and AMD chipsets have hwrng chips.
  Their Linux drivers usually don't credit entropy.
  (But there's `rng_core.default_quality=1000`, see above.)

* Various embedded boards have hwrng chips.
  Some drivers automatically credit entropy, others do not.
  Some WiFi chips appear to have hwrng sources too, and
  they usually do not credit entropy for them.

* `virtio-rng` is used in virtualized environments and retrieves random data
  from the VM host. It credits full entropy.

* The EFI firmware typically provides a RNG API.
  When transitioning from UEFI to kernel mode Linux will query some random data through it, and feed it into
  the pool, but not credit entropy to it.
  What kind of random source is behind the EFI RNG API is often not entirely clear, but it hopefully is some kind of hardware source.

If neither of these are available (in fact, even if they are), Linux generates
entropy from various non-hwrng sources in various subsystems, all of which
ultimately are rooted in IRQ noise, a very "slow" source of entropy, in
particular in virtualized environments.

## `systemd`'s Use of Random Numbers

systemd is responsible for bringing up the OS.
It generally runs as the first userspace process the kernel invokes.
Because of that it runs at a time where the entropy pool is typically not yet initialized,
and thus requests to acquire random bytes will either be delayed, will fail or result in a noisy kernel log
message (see above).

Various other components run during early boot that require random bytes.
For example, initrds nowadays communicate with encrypted networks or access
encrypted storage which might need random numbers.
systemd itself requires random numbers as well, including for the following uses:

* systemd assigns 'invocation' UUIDs to all services it invokes that uniquely
  identify each invocation.
  This is useful to retain a global handle on a specific service invocation and relate it to other data.
  For example, log data collected by the journal usually includes the invocation UUID
  and thus the runtime context the service manager maintains can be neatly matched up with
  the log data a specific service invocation generated.
  systemd also initializes `/etc/machine-id` with a randomized UUID.
  (systemd also makes use of the randomized "boot id" the kernel exposes in `/proc/sys/kernel/random boot_id`).
  These UUIDs are exclusively Type 4 UUIDs, i.e. randomly generated ones.

* systemd maintains various hash tables internally.
  In order to harden them against
  [collision attacks](https://www.cs.auckland.ac.nz/~mcw/Teaching/refs/misc/denial-of-service.pdf)
  they are seeded with random numbers.

* At various places systemd needs random bytes for temporary file name
  generation, UID allocation randomization, and similar.

* systemd-resolved and systemd-networkd use random number generators to harden
  the protocols they implement against packet forgery.

* systemd-udevd and systemd-nspawn can generate randomized MAC addresses for
  network devices.

Note that these cases generally do not require a cryptographic-grade random
number generator, as most of these utilize random numbers to minimize risk of
collision and not to generate secret key material.
However, they usually do require "medium-grade" random data.
For example: systemd's hash-maps are reseeded if they grow beyond certain thresholds (and thus collisions are more likely).
This means they are generally fine with low-quality (even constant)random numbers initially as long as they get better with time, so that collision attacks are eventually thwarted as better, non-guessable seeds are
acquired.

## Keeping `systemd'`s Demand on the Kernel Entropy Pool Minimal

Since most of systemd's own use of random numbers do not require
cryptographic-grade RNGs, it tries to avoid blocking reads to the kernel's RNG,
opting instead for using `getrandom(GRND_INSECURE)`.
After the pool is initialized, this is identical to `getrandom(0)`, returning cryptographically
secure random numbers, but before it's initialized it has the nice effect of
not blocking system boot.

## `systemd`'s Support for Filling the Kernel Entropy Pool

systemd has various provisions to ensure the kernel entropy is filled during
boot, in order to ensure the entropy pool is filled up quickly.

1. When systemd's PID 1 detects it runs in a virtualized environment providing
   the `virtio-rng` interface it will load the necessary kernel modules to make
   use of it during earliest boot, if possible — much earlier than regular
   kernel module loading done by `systemd-udevd.service`.
   This should ensure that in VM environments the entropy pool is quickly filled, even before
   systemd invokes the first service process — as long as the VM environment
   provides virtualized RNG hardware (and VM environments really should!).

2. The
   [`systemd-random-seed.service`](https://www.freedesktop.org/software/systemd/man/systemd-random-seed.service.html)
   system service will load a random seed from `/var/lib/systemd/random-seed`
   into the kernel entropy pool.
   By default it does not credit entropy for it though, since the seed is — more often than not — not reset when 'golden' master images of an OS are created, and thus replicated into every installation.
   If OS image builders carefully reset the random seed file before generating the image it should be safe to credit entropy, which can be enabled by setting the `$SYSTEMD_RANDOM_SEED_CREDIT` environment variable
   for the service to `1` (or even `force`, see man page).
   Note however, that this service typically runs relatively late during early boot: long after
   the initrd completed, and after the `/var/` file system became writable.
   This is usually too late for many applications, it is hence not advised to rely exclusively on this functionality to seed the kernel's entropy pool.
   Also note that this service synchronously waits until the kernel's entropy pool is initialized before completing start-up.
   It may thus be used by other services as synchronization point to order against, if they
   require an initialized entropy pool to operate correctly.

3. The
   [`systemd-boot`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)
   EFI boot loader included in systemd is able to maintain and provide a random
   seed stored in the EFI System Partition (ESP) to the booted OS, which allows
   booting up with a fully initialized entropy pool from earliest boot on.
   During installation of the boot loader (or when invoking
   [`bootctlrandom-seed`](https://www.freedesktop.org/software/systemd/man/bootctl.html#random-seed))
   a seed file with an initial seed is placed in a file `/loader/random-seed` in the ESP.
   In addition, an identically sized randomized EFI variable called the 'system token' is set, which is written to the machine's firmware NVRAM.

   During boot, when `systemd-boot` finds both the random seed file and the
   system token they are combined and hashed with SHA256 (in counter mode, to
   generate sufficient data), to generate a new random seed file to store in
   the ESP as well as a random seed to pass to the OS kernel.
   The new random seed file for the ESP is then written to the ESP, ensuring this is completed
   before the OS is invoked.

   The kernel then reads the random seed that the boot loader passes to it, via
   the EFI configuration table entry, `LINUX_EFI_RANDOM_SEED_TABLE_GUID`
   (1ce1e5bc-7ceb-42f2-81e5-8aadf180f57b), which is allocated with pool memory
   of type `EfiACPIReclaimMemory`.
   Its contents have the form:
   ```
   struct linux_efi_random_seed {
       u32     size; // of the 'seed' array in bytes
       u8      seed[];
   };
   ```
   The size field is generally set to 32 bytes, and the seed field includes a
   hashed representation of any prior seed in `LINUX_EFI_RANDOM_SEED_TABLE_GUID`
   together with the new seed.

   This mechanism is able to safely provide an initialized entropy pool before
   userspace even starts and guarantees that different seeds are passed from
   the boot loader to the OS on every boot (in a way that does not allow
   regeneration of an old seed file from a new seed file).

   Moreover, when an OS image is replicated between multiple images and the random seed is not reset, this will still result in different random seeds being passed to the OS, as the per-machine 'system token' is specific to the physical host, and not included in OS disk images.

   If the 'system token' is properly initialized and kept sufficiently secret it should not be possible to
   regenerate the entropy pool of different machines, even if this seed is the
   only source of entropy.

   Note that the writes to the ESP needed to maintain the random seed should be minimal.
   Because the size of the random seed file is generally set to 32 bytes,
   updating the random seed in the ESP should be doable safely with a single
   sector write (since hard-disk sectors typically happen to be 512 bytes long,
   too), which should be safe even with FAT file system drivers built into
   low-quality EFI firmwares.

4. A kernel command line option `systemd.random_seed=` may be used to pass in a
   base64 encoded seed to initialize the kernel's entropy pool from during
   early service manager initialization.
   This option is only safe in testing environments, as the random seed passed this way is accessible to
   unprivileged programs via `/proc/cmdline`.
   Using this option outside of testing environments is a security problem since cryptographic key material
   derived from the entropy pool initialized with a seed accessible to
   unprivileged programs should not be considered secret.

With the four mechanisms described above it should be possible to provide
early-boot entropy in most cases. Specifically:

1. On EFI systems, `systemd-boot`'s random seed logic should make sure good
   entropy is available during earliest boot — as long as `systemd-boot` is
   used as boot loader, and outside of virtualized environments.

2. On virtualized systems, the early `virtio-rng` hookup should ensure entropy
   is available early on — as long as the VM environment provides virtualized
   RNG devices, which they really should all do in 2019.
   Complain to your hosting provider if they don't.
   For VMs used in testing environments, `systemd.random_seed=` may be used as an alternative to a virtualized RNG.

3. In general, systemd's own reliance on the kernel entropy pool is minimal
   (due to the use of `GRND_INSECURE`).

4. In all other cases, `systemd-random-seed.service` will help a bit, but — as
   mentioned — is too late to help with early boot.

This primarily leaves two kind of systems in the cold:

1. Some embedded systems. Many embedded chipsets have hwrng functionality these
   days.
   Consider using them while crediting entropy.
   (i.e. `rng_core.default_quality=1000` on the kernel command line is your friend).
   Or accept that the system might take a bit longer to boot.
   Alternatively, consider implementing a solution similar to systemd-boot's random seed concept in your platform's boot loader.

2. Virtualized environments that lack both virtio-rng and RDRAND, outside of
   test environments.
   Tough luck. Talk to your hosting provider, and ask them to fix this.

3. Also note: if you deploy an image without any random seed and/or without
   installing any 'system token' in an EFI variable, as described above, this
   means that on the first boot no seed can be passed to the OS either.
   However, as the boot completes (with entropy acquired elsewhere),
   systemd will automatically install both a random seed in the GPT and a
   'system token' in the EFI variable space, so that any future boots will have
   entropy from earliest boot on — all provided `systemd-boot` is used.

## Frequently Asked Questions

1. *Why don't you just use getrandom()? That's all you need!*

   Did you read any of the above? getrandom() is hooked to the kernel entropy
   pool, and during early boot it's not going to be filled yet, very likely.
   We do use it in many cases, but not in all.
   Please read the above again!

2. *Why don't you use
   [getentropy()](https://man7.org/linux/man-pages/man3/getentropy.3.html)?
   That's all you need!*

   Same story. That call is just a different name for `getrandom()` with
   `flags` set to zero, and some additional limitations, and thus it also needs
   the kernel's entropy pool to be initialized, which is the whole problem we
   are trying to address here.

3. *Why don't you generate your UUIDs with
   [`uuidd`](https://man7.org/linux/man-pages/man8/uuidd.8.html)?
   That's all you need!*

   First of all, that's a system service, i.e. something that runs as "payload"
   of systemd, long after systemd is already up and hence can't provide us
   UUIDs during earliest boot yet.
   Don't forget: to assign the invocation UUID for the `uuidd.service` start we already need a UUID that the service is supposed to provide us.
   More importantly though, `uuidd` needs state/a random seed/a MAC address/host ID to operate, all of which are not available during early boot.

4. *Why don't you generate your UUIDs with `/proc/sys/kernel/random/uuid`?
   That's all you need!*

   This is just a different, more limited interface to `/dev/urandom`. It gains
   us nothing.

5. *Why don't you use
   [`rngd`](https://github.com/nhorman/rng-tools),
   [`haveged`](http://www.issihosts.com/haveged/),
   [`egd`](http://egd.sourceforge.net/)?
   That's all you need!*

   Like `uuidd` above these are system services, hence come too late for our use-case.
   In addition much of what `rngd` provides appears to be equivalent
   to `CONFIG_RANDOM_TRUST_CPU=y` or `rng_core.default_quality=1000`, except
   being more complex and involving userspace.
   These services partly measure system behavior (such as scheduling effects) which the kernel either
   already feeds into its pool anyway (and thus shouldn't be fed into it a
   second time, crediting entropy for it a second time) or is at least
   something the kernel could much better do on its own.
   Hence, if what these daemons do is still desirable today, this would be much better implemented
   in kernel (which would be very welcome of course, but wouldn't really help
   us here in our specific problem, see above).

6. *Why don't you use [`arc4random()`](https://man.openbsd.org/arc4random.3)?
   That's all you need!*

   This doesn't solve the issue, since it requires a nonce to start from, and
   it gets that from `getrandom()`, and thus we have to wait for random pool
   initialization the same way as calling `getrandom()` directly.

   `arc4random()` is nothing more than optimization, in fact it
   implements similar algorithms that the kernel entropy pool implements
   anyway, hence besides being able to provide random bytes with higher
   throughput there's little it gets us over just using `getrandom()`.

   Also, it's not supported by glibc.
   And as long as that's the case we are not keen on using it, as we'd have to maintain that on our own, and we don't want to maintain our own cryptographic primitives if we don't have to.
   Since systemd's uses are not performance relevant (besides the pool initialization
   delay, which this doesn't solve), there's hence little benefit for us to call these functions.
   That said, if glibc learns these APIs one day, we'll certainly make use of them where appropriate.

7. *This is boring: NetBSD had [boot loader entropy seed support](https://man.netbsd.org/entropy.7) since ages!*

   Yes, NetBSD has that, and the above is inspired by that (note though: this
   article is about a lot more than that).
   NetBSD's support is not really safe, since it neither updates the random seed before using it,
   nor has any safeguards against replicating the same disk image with its random seed on
   multiple machines (which the 'system token' mentioned above is supposed to address).
   This means reuse of the same random seed by the boot loader is much more likely.

8. *Why does PID 1 upload the boot loader provided random seed into kernel
   instead of kernel doing that on its own?*

   That's a good question. Ideally the kernel would do that on its own, and we
   wouldn't have to involve userspace in this.

9. *What about non-EFI?*

   The boot loader random seed logic described above uses EFI variables to pass
   the seed from the boot loader to the OS.
   Other systems might have similar functionality though, and it shouldn't be too hard to implement something
   similar for them.
   Ideally, we'd have an official way to pass such a seed as part of the `struct boot_params` from the boot loader to the kernel, but this is currently not available.

10. *I use a different boot loader than `systemd-boot`, I'd like to use boot
    loader random seeds too!*

    Well, consider just switching to `systemd-boot`, it's worth it. See
    [systemd-boot(7)](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)
    for an introduction why. That said, any boot loader can re-implement the
    logic described above, and can pass a random seed that systemd as PID 1
    will then upload into the kernel's entropy pool. For details see the
    [Boot Loader Interface](/BOOT_LOADER_INTERFACE) documentation.

11. *Why not pass the boot loader random seed via kernel command line instead
    of as EFI variable?*

    The kernel command line is accessible to unprivileged processes via `/proc/cmdline`.
    It's not desirable if unprivileged processes can use this information to possibly gain too much information about the current state of the kernel's entropy pool.

    That said, we actually do implement this with the `systemd.random_seed=`
    kernel command line option.
    Don't use this outside of testing environments, however, for the aforementioned reasons.

12. *Why doesn't `systemd-boot` rewrite the 'system token' too each time
    when updating the random seed file stored in the ESP?*

    The system token is stored as persistent EFI variable, i.e. in some form of NVRAM.
    These memory chips tend be of low quality in many machines, and
    hence we shouldn't write them too often.
    Writing them once during installation should generally be OK, but rewriting them on every single
    boot would probably wear the chip out too much, and we shouldn't risk that.

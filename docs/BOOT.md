---
title: systemd-boot UEFI Boot Manager
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# systemd-boot UEFI Boot Manager

systemd-boot is a UEFI boot manager which executes configured EFI images. The default entry is selected by a configured pattern (glob) or an on-screen menu.

systemd-boot operates on the EFI System Partition (ESP) only. Configuration file fragments, kernels, initrds, other EFI images need to reside on the ESP.

Linux kernels need to be built with CONFIG\_EFI\_STUB to be able to be directly executed as an EFI image.

systemd-boot reads simple and entirely generic boot loader configuration files; one file per boot loader entry to select from. All files need to reside on the ESP.

Pressing the Space key (or most other keys actually work too) during bootup will show an on-screen menu with all configured loader entries to select from.

Pressing Enter on the selected entry loads and starts the EFI image.

If no timeout is configured, which is the default setting, and no key pressed during bootup, the default entry is executed right away.

![systemd-boot menu](/assets/systemd-boot-menu.png)

All configuration files are expected to be 7-bit ASCII or valid UTF8. The loader configuration file understands the following keywords:

| Config  |
|---------|------------------------------------------------------------|
| default | pattern to select the default entry in the list of entries |
| timeout | timeout in seconds for how long to show the menu           |


The entry configuration files understand the following keywords:

| Entry  |
|--------|------------------------------------------------------------|
| title | text to show in the menu |
| version | version string to append to the title when the title is not unique |
| machine-id | machine identifier to append to the title when the title is not unique |
| efi | executable EFI image |
| options | options to pass to the EFI image / kernel command line |
| linux | linux kernel image (systemd-boot still requires the kernel to have an EFI stub) |
| initrd | initramfs image (systemd-boot just adds this as option initrd=) |


Examples:
```
/boot/loader/loader.conf
timeout 3
default 6a9857a393724b7a981ebb5b8495b9ea-*

/boot/loader/entries/6a9857a393724b7a981ebb5b8495b9ea-3.8.0-2.fc19.x86_64.conf
title      Fedora 19 (Rawhide)
version    3.8.0-2.fc19.x86_64
machine-id 6a9857a393724b7a981ebb5b8495b9ea
linux      /6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/linux
initrd     /6a9857a393724b7a981ebb5b8495b9ea/3.8.0-2.fc19.x86_64/initrd
options    root=UUID=f8f83f73-df71-445c-87f7-31f70263b83b quiet

/boot/loader/entries/custom-kernel.conf
title      My kernel
efi        /bzImage
options    root=PARTUUID=084917b7-8be2-4e86-838d-f771a9902e08

/boot/loader/entries/custom-kernel-initrd.conf
title      My kernel with initrd
linux      /bzImage
initrd     /initrd.img
options    root=PARTUUID=084917b7-8be2-4e86-838d-f771a9902e08 quiet
```


While the menu is shown, the following keys are active:

| Keys   |
|--------|------------------------------------------------------------|
| Up/Down | Select menu entry |
| Enter | boot the selected entry |
| d | select the default entry to boot (stored in a non-volatile EFI variable) |
| t/T | adjust the timeout (stored in a non-volatile EFI variable) |
| e | edit the option line (kernel command line) for this bootup to pass to the EFI image |
| Q | quit |
| v | show the systemd-boot and UEFI version |
| P | print the current configuration to the console |
| h | show key mapping |

Hotkeys to select a specific entry in the menu, or when pressed during bootup to boot the entry right-away:



| Keys   |
|--------|------------------------------------------------------------|
| l | Linux |
| w | Windows |
| a | macOS |
| s | EFI Shell |
| 1-9 | number of entry |

Some EFI variables control the loader or exported the loaders state to the started operating system. The vendor UUID `4a67b082-0a4c-41cf-b6c7-440b29bb8c4f` and the variable names are supposed to be shared across all loaders implementations which follow this scheme of configuration:

| EFI Variables |
|---------------|------------------------|-------------------------------|
| LoaderEntryDefault | entry identifier to select as default at bootup, ignoring boot assessment | non-volatile |
| LoaderEntryPreferred | entry identifier to select as default at bootup, respecting boot assessment | non-volatile |
| LoaderEntrySysFail | sysfail entry identifier | non-volatile |
| LoaderSysFailReason | system failure reason | volatile |
| LoaderConfigTimeout | timeout in seconds to show the menu | non-volatile |
| LoaderEntryOneShot | entry identifier to select at the next and only the next bootup | non-volatile |
| LoaderDeviceIdentifier | list of identifiers of the volume the loader was started from | volatile |
| LoaderDevicePartUUID | partition GPT UUID of the ESP systemd-boot was executed from | volatile |


Links:

[https://github.com/systemd/systemd](https://github.com/systemd/systemd)

[https://uapi-group.org/specifications/specs/boot_loader_specification/](https://uapi-group.org/specifications/specs/boot_loader_specification/)

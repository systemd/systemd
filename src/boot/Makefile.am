#
#  This file is part of systemd-boot
#
#  Copyright (C) 2018 James Hilliard <james.hilliard1@gmail.com>
#
#  systemd-boot is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.
#
#  systemd-boot is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with systemd; If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

bootlibdir = $(prefix)/lib/systemd/boot/efi

if ENABLE_EFI
if HAVE_BLKID
if HAVE_GNUEFI
efi_cppflags = \
	$(EFI_CPPFLAGS) \
	-I$(top_builddir) -include config.h \
	-I$(EFI_INC_DIR)/efi \
	-I$(EFI_INC_DIR)/efi/$(EFI_ARCH) \
	-DEFI_MACHINE_TYPE_NAME=\"$(EFI_MACHINE_TYPE_NAME)\"

efi_cflags = \
	$(EFI_CFLAGS) \
	-Wall \
	-Wextra \
	-std=gnu90 \
	-nostdinc \
	-ggdb -O0 \
	-fpic \
	-fshort-wchar \
	-nostdinc \
	-ffreestanding \
	-fno-strict-aliasing \
	-fno-stack-protector \
	-Wsign-compare \
	-Wno-missing-field-initializers

if ARCH_X86_64
efi_cflags += \
	-mno-red-zone \
	-mno-sse \
	-mno-mmx \
	-DEFI_FUNCTION_WRAPPER \
	-DGNU_EFI_USE_MS_ABI
endif

if ARCH_IA32
efi_cflags += \
	-mno-sse \
	-mno-mmx
endif

efi_ldflags = \
	$(EFI_LDFLAGS) \
	-T $(EFI_LDS_DIR)/elf_$(EFI_ARCH)_efi.lds \
	-shared \
	-Bsymbolic \
	-nostdlib \
	-znocombreloc \
	-L $(EFI_LIB_DIR) \
	$(EFI_LDS_DIR)/crt0-efi-$(EFI_ARCH).o

# Aarch64 and ARM32 don't have an EFI capable objcopy. Use 'binary' instead,
# and add required symbols manually.
if ARCH_AARCH64
efi_ldflags += --defsym=EFI_SUBSYSTEM=0xa
EFI_FORMAT = -O binary
else
EFI_FORMAT = --target=efi-app-$(EFI_ARCH)
endif
endif
endif

# ------------------------------------------------------------------------------
systemd_boot_headers = \
	efi/util.h \
	efi/console.h \
	efi/graphics.h \
	efi/measure.h \
	efi/disk.h

systemd_boot_sources = \
	efi/util.c \
	efi/console.c \
	efi/graphics.c \
	efi/disk.c \
	efi/measure.c \
	efi/boot.c

EXTRA_DIST = $(systemd_boot_sources) $(systemd_boot_headers)

systemd_boot_objects = $(addprefix $(top_builddir)/,$(systemd_boot_sources:.c=.o))
systemd_boot_solib = $(top_builddir)/efi/systemd_boot.so
systemd_boot = systemd-boot$(EFI_MACHINE_TYPE_NAME).efi

if ENABLE_EFI
if HAVE_GNUEFI
bootlib_DATA = $(systemd_boot)

$(top_builddir)/efi/%.o: $(top_srcdir)/efi/%.c $(addprefix $(top_srcdir)/,$(systemd_boot_headers))
	@$(MKDIR_P) $(top_builddir)/efi/
	$(AM_V_CC)$(EFI_CC) $(efi_cppflags) $(efi_cflags) -c $< -o $@

$(systemd_boot_solib): $(systemd_boot_objects)
	$(AM_V_CCLD)$(LD) $(efi_ldflags) $(systemd_boot_objects) \
		-o $@ -lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name); \
	nm -D -u $@ | grep ' U ' && exit 1 || :

$(systemd_boot): $(systemd_boot_solib)
	$(AM_V_GEN)$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic \
	  -j .dynsym -j .rel -j .rela -j .reloc $(EFI_FORMAT) $< $@
endif
endif

CLEANFILES = $(systemd_boot_objects) $(systemd_boot_solib) $(systemd_boot)

# ------------------------------------------------------------------------------
stub_headers = \
	efi/util.h \
	efi/pe.h \
	efi/disk.h \
	efi/graphics.h \
	efi/splash.h \
	efi/measure.h \
	efi/linux.h

stub_sources = \
	efi/util.c \
	efi/pe.c \
	efi/disk.c \
	efi/graphics.c \
	efi/splash.c \
	efi/linux.c \
	efi/measure.c \
	efi/stub.c

EXTRA_DIST += \
	$(stub_sources) \
	$(stub_headers) \
	test/splash.bmp

stub_objects = $(addprefix $(top_builddir)/,$(stub_sources:.c=.o))
stub_solib = $(top_builddir)/efi/stub.so
stub = linux$(EFI_MACHINE_TYPE_NAME).efi.stub

if ENABLE_EFI
if HAVE_GNUEFI
bootlib_DATA += $(stub)

$(top_builddir)/efi/%.o: $(top_srcdir)/efi/%.c $(addprefix $(top_srcdir)/,$(stub_headers))
	@$(MKDIR_P) $(top_builddir)/efi/
	$(AM_V_CC)$(EFI_CC) $(efi_cppflags) $(efi_cflags) -c $< -o $@

$(stub_solib): $(stub_objects)
	$(AM_V_CCLD)$(LD) $(efi_ldflags) $(stub_objects) \
		-o $@ -lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name); \
	nm -D -u $@ | grep ' U ' && exit 1 || :

$(stub): $(stub_solib)
	$(AM_V_GEN)$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic \
	  -j .dynsym -j .rel -j .rela -j .reloc $(EFI_FORMAT) $< $@
endif
endif

CLEANFILES += $(stub_objects) $(stub_solib) $(stub)


# ------------------------------------------------------------------------------
CLEANFILES += test-efi-disk.img

test-efi-disk.img: $(systemd_boot) $(stub) ../../test/splash.bmp ../../test/test-efi-create-disk.sh
	$(AM_V_GEN)../../test/test-efi-create-disk.sh

test-efi: test-efi-disk.img
	$(QEMU) -machine accel=kvm -m 1024 -bios $(QEMU_BIOS) -snapshot test-efi-disk.img

EXTRA_DIST += test/test-efi-create-disk.sh

endif
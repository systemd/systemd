#!/bin/bash -e

out="$1"
systemd_efi="$2"
boot_stub="$3"
splash_bmp="$4"
if [ -z "$out" -o -z "$systemd_efi" -o -z "$boot_stub" -o -z "$splash_bmp" ]; then
    exit 1
fi

# create GPT table with EFI System Partition
rm -f "$out"
dd if=/dev/null of="$out" bs=1M seek=512 count=1 status=none
parted --script "$out" "mklabel gpt" "mkpart ESP fat32 1MiB 511MiB" "set 1 boot on"

# create FAT32 file system
LOOP=$(losetup --show -f -P "$out")
mkfs.vfat -F32 ${LOOP}p1
mkdir -p mnt
mount ${LOOP}p1 mnt

mkdir -p mnt/EFI/{BOOT,systemd}
cp "$systemd_efi" mnt/EFI/BOOT/BOOTX64.efi

[ -e /boot/shellx64.efi ] && cp /boot/shellx64.efi mnt/

mkdir mnt/EFI/Linux
echo -n "foo=yes bar=no root=/dev/fakeroot debug rd.break=initqueue" >mnt/cmdline.txt
objcopy \
    --add-section .osrel=/etc/os-release --change-section-vma .osrel=0x20000 \
    --add-section .cmdline=mnt/cmdline.txt --change-section-vma .cmdline=0x30000 \
    --add-section .splash="$splash_bmp" --change-section-vma .splash=0x40000 \
    --add-section .linux=/boot/$(cat /etc/machine-id)/$(uname -r)/linux --change-section-vma .linux=0x2000000 \
    --add-section .initrd=/boot/$(cat /etc/machine-id)/$(uname -r)/initrd --change-section-vma .initrd=0x3000000 \
    "$boot_stub" mnt/EFI/Linux/linux-test.efi

# install entries
mkdir -p mnt/loader/entries
echo -e "timeout 3\n" > mnt/loader/loader.conf
echo -e "title Test\nefi /test\n" > mnt/loader/entries/test.conf
echo -e "title Test2\nlinux /test2\noptions option=yes word number=1000 more\n" > mnt/loader/entries/test2.conf
echo -e "title Test3\nlinux /test3\n" > mnt/loader/entries/test3.conf
echo -e "title Test4\nlinux /test4\n" > mnt/loader/entries/test4.conf
echo -e "title Test5\nefi /test5\n" > mnt/loader/entries/test5.conf
echo -e "title Test6\nlinux /test6\n" > mnt/loader/entries/test6.conf

sync
umount mnt
rmdir mnt
losetup -d $LOOP

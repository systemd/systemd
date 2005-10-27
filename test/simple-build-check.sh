#/bin/sh

EXTRAS="\
	extras/scsi_id \
	extras/ata_id \
	extras/volume_id \
	extras/usb_id \
	extras/dasd_id \
	extras/cdrom_id \
	extras/edd_id \
	extras/floppy \
	extras/run_directory \
	extras/firmware"

[ -z "$KERNEL_DIR" ] && KERNEL_DIR=/lib/modules/`uname -r`/build
echo KERNEL_DIR: "$KERNEL_DIR"

# with debug
make clean EXTRAS="$EXTRAS" >/dev/null
make all -j4 $MAKEOPTS DEBUG=true EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

# without any logging
make clean EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS USE_LOG=false EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

# klibc and debug
make clean EXTRAS="$EXTRAS" >/dev/null
make all -j4 $MAKEOPTS USE_KLIBC=true DEBUG=true EXTRAS="$EXTRAS" KERNEL_DIR="$KERNEL_DIR" || exit
echo -e "\n\n"

# install in temporary dir and show it
TEMPDIR="`pwd`/.tmp"
rm -rf $TEMPDIR
mkdir $TEMPDIR
make clean EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS DESTDIR="$TEMPDIR" EXTRAS="$EXTRAS" || exit
make install DESTDIR="$TEMPDIR" EXTRAS="$EXTRAS" || exit
echo -e "\nInstalled tree:"
find $TEMPDIR
rm -rf $TEMPDIR

make clean EXTRAS="$EXTRAS" >/dev/null

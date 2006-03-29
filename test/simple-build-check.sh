#/bin/sh

EXTRAS="\
	extras/path_id \
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

# with debug
make clean EXTRAS="$EXTRAS" >/dev/null
make all -j4 $MAKEOPTS DEBUG=true EXTRAS="$EXTRAS" || exit
echo -e "\n\n"

# without any logging
make clean EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS USE_LOG=false EXTRAS="$EXTRAS" || exit
echo -e "\n\n"

# klibc build
if [ -n "$KLCC" -a -e "$KLCC" ]; then
	echo KLCC: "$KLCC"
	make clean EXTRAS="$EXTRAS" >/dev/null
	make all -j4 $MAKEOPTS USE_KLIBC=true DEBUG=true EXTRAS="$EXTRAS" KLCC="$KLCC" || exit
	echo -e "\n\n"
fi

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

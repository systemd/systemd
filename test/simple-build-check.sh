#/bin/sh

EXTRAS="\
	extras/chassis_id \
	extras/scsi_id \
	extras/ata_id \
	extras/volume_id \
	extras/usb_id \
	extras/dasd_id \
	extras/floppy \
	extras/run_directory"

[ -z "$KERNEL_DIR" ] && KERNEL_DIR=/lib/modules/`uname -r`/build
echo KERNEL_DIR: "$KERNEL_DIR"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS EXTRAS="$EXTRAS" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all -j4 $MAKEOPTS DEBUG=true EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS USE_LOG=false EXTRAS="$EXTRAS"  || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all -j4 $MAKEOPTS USE_KLIBC=true DEBUG=true EXTRAS="$EXTRAS" KERNEL_DIR="$KERNEL_DIR" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
make all $MAKEOPTS USE_KLIBC=true USE_LOG=false EXTRAS="$EXTRAS" KERNEL_DIR="$KERNEL_DIR" || exit
echo -e "\n\n"

make spotless EXTRAS="$EXTRAS" >/dev/null
echo "build test completed successfully"

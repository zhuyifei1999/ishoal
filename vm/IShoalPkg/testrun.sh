#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# https://stackoverflow.com/a/34676160
WORK_DIR=`mktemp -d`

cd "$WORK_DIR"

function cleanup_tmp {
  cd "$DIR"
  rm -rf "$WORK_DIR"
}

trap cleanup_tmp EXIT

do_copy() {
  mkdir -p rootfs/EFI/Boot/
  cp /var/cache/kbuild/arch/x86/boot/bzImage rootfs/linux.efi
  cp "${DIR}/../LodePngPkg/LodePngDecode.efi" rootfs/LodePngDecode.efi
  cp "${DIR}/IShoal.efi" rootfs/EFI/Boot/bootx64.efi
}

test_qemu() {
  do_copy
  qemu-system-x86_64 --enable-kvm -bios /usr/share/edk2-ovmf/OVMF_CODE.fd -m 256M -drive format=raw,file=fat:rw:rootfs -net none
}

test_vbox() {
  truncate -s $((16 * 1048576)) test.img
  mkfs.fat test.img

  mkdir rootfs
  guestmount -a test.img -m /dev/sda rootfs

  do_copy
  umount rootfs && sleep 1

  qemu-img convert test.img -O vdi test.vdi

  mv test.vdi "${DIR}/test.vdi"
}

test_qemu

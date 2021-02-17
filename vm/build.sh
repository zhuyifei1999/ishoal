#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

REPO="$(realpath -s ${DIR}/..)"

# https://stackoverflow.com/a/34676160
WORK_DIR=`mktemp -d`

cd "$WORK_DIR"

function cleanup_tmp {
  cd "$DIR"
  rm -rf "$WORK_DIR"
}

trap cleanup_tmp EXIT

mkdir rootfs

truncate -s $((128 * 1048576)) disk.img
fdisk disk.img << EOF
g
n
1
2048
32767
n
2
32768
262110
w
EOF

BOOT="$(sudo losetup --offset $(( 2048 * 512 )) --sizelimit $(( 30720 * 512 )) --show --find disk.img)"
ROOT="$(sudo losetup --offset $(( 32768 * 512 )) --sizelimit $(( 229343 * 512 )) --show --find disk.img)"

sudo mkfs.fat "$BOOT"
sudo mkfs.btrfs -M "$ROOT"

sudo mount -o compress,discard "$ROOT" rootfs
sudo mkdir -p rootfs/boot
sudo mount "$BOOT" rootfs/boot

MOUNTED=true

function do_cleanup_mnt {
  if $MOUNTED; then
    sudo umount rootfs/boot
    sudo umount rootfs
    sudo losetup --detach "$BOOT"
    sudo losetup --detach "$ROOT"
  fi
}

function cleanup_mnt {
  do_cleanup_mnt
  cleanup_tmp
}

trap cleanup_mnt EXIT

mkdir -p "${REPO}/vm/binpkgs"

sudo docker run \
  -v $REPO:$REPO \
  -v $PWD:$PWD \
  -v "${REPO}/vm/binpkgs":/var/cache/binpkgs \
  -w $PWD \
  -e REPO="${REPO}" \
  --tmpfs /var/tmp/portage:exec \
  --tmpfs /var/cache/distfiles \
  --tmpfs /var/db/repos \
  --security-opt seccomp=unconfined \
  --cap-add=SYS_PTRACE \
  --rm -i \
  gentoo/stage3:amd64-nomultilib \
  bash "${REPO}/vm/build-inner.sh"

fstrim -v rootfs

do_cleanup_mnt
MOUNTED=false

qemu-img convert disk.img -S 4k -O vmdk -o subformat=streamOptimized ishoal-disk001.vmdk
cp "${DIR}/ishoal.ovf" ishoal.ovf

echo "SHA1 (ishoal-disk001.vmdk) = $(sha1sum ishoal-disk001.vmdk | cut -d\  -f 1 )" >> ishoal.mf
echo "SHA1 (ishoal.ovf) = $(sha1sum ishoal.ovf | cut -d\  -f 1 )" >> ishoal.mf

tar cvf ishoal.ova ishoal.ovf ishoal-disk001.vmdk ishoal.mf

cp -a ishoal.ova "${REPO}/vm/ishoal.ova"

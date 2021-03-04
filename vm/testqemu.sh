#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

OVA_PATH="$(realpath "${1:-$DIR/ishoal.ova}")"

# https://stackoverflow.com/a/34676160
WORK_DIR=`mktemp -d`

cd "$WORK_DIR"

function cleanup_tmp {
  cd "$DIR"
  rm -rf "$WORK_DIR"
}

trap cleanup_tmp EXIT

cp "$OVA_PATH" ishoal.ova

tar xvf ishoal.ova

qemu-img convert ishoal-disk001.vmdk -O qcow2 ishoal.qcow2

qemu-system-x86_64 \
  --enable-kvm \
  --cpu max \
  -m 128M \
  -drive format=qcow2,file=ishoal.qcow2 \
  -bios /usr/share/edk2-ovmf/OVMF_CODE.fd \
  -nic user,model=e1000

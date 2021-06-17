#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BUILD_LOGO="${BUILD_LOGO:-true}"
REPO="$(realpath -s ${DIR}/..)"

# https://stackoverflow.com/a/34676160
WORK_DIR=`mktemp -d`

cd "$WORK_DIR"

function cleanup_tmp {
  cd "$DIR"
  rm -rf "$WORK_DIR"
}

trap cleanup_tmp EXIT

# https://unix.stackexchange.com/a/423052
PORT="$(comm -23 <(seq 49152 65535 | sort) <(ss -Htan | awk '{print $4}' | cut -d':' -f2 | sort -u) | shuf | head -n 1)"
wget https://cloud-images.ubuntu.com/hirsute/current/hirsute-server-cloudimg-amd64-disk-kvm.img -O cloudimg.img
qemu-img resize cloudimg.img +8G

# Or https://github.com/canonical/cloud-utils.git
git clone https://salsa.debian.org/cloud-team/cloud-utils.git

ssh-keygen -f sshkey -N '' -C 'ishoal-builder'
PUBKEY="$(cat sshkey.pub)"
cat > user-data << EOF
#cloud-config
chpasswd: { expire: False }
ssh_authorized_keys:
  - $PUBKEY
EOF

cloud-utils/bin/cloud-localds user-data.img user-data -f vfat

mkdir output
mkdir -p "${REPO}/vm/binpkgs"

setsid qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -machine accel=kvm:xen:hax:hvf:whpx:tcg \
  -smp "$(nproc)" \
  -m 10G \
  -display none \
  -serial mon:stdio \
  -device virtio-rng-pci \
  -netdev "user,id=virtual,hostfwd=tcp:127.0.0.1:${PORT}-:22" \
  -device virtio-net-pci,netdev=virtual \
  -fsdev "local,multidevs=remap,id=vfs1,path=${REPO},security_model=none,readonly" \
  -device virtio-9p-pci,fsdev=vfs1,mount_tag=/dev/source \
  -fsdev "local,multidevs=remap,id=vfs2,path=$(pwd)/output,security_model=none" \
  -device virtio-9p-pci,fsdev=vfs2,mount_tag=/dev/output \
  -fsdev "local,multidevs=remap,id=vfs3,path=${REPO}/vm/binpkgs,security_model=none" \
  -device virtio-9p-pci,fsdev=vfs3,mount_tag=/dev/binpkgs \
  -drive id=fsdrv,if=none,file=cloudimg.img,cache=unsafe,discard=unmap,detect-zeroes=unmap \
  -device virtio-blk-pci,drive=fsdrv \
  -drive id=confdrv,if=none,file=user-data.img,format=raw \
  -device virtio-blk-pci,drive=confdrv &
  QEMU_PID=$!

RUNNING=true
function cleanup_qemu {
  if $RUNNING; then
    kill "$QEMU_PID" || true
  fi
  cleanup_tmp
}

trap cleanup_qemu EXIT
sleep 1

while ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i sshkey ubuntu@127.0.0.1 -p "${PORT}" true; do
  sleep 5
done

# shellcheck disable=SC2087
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i sshkey ubuntu@127.0.0.1 -p "${PORT}" << EOF
set -ex

SCRIPT=$(mktemp)

cat > \$SCRIPT << 'INNEREOF'
set -ex

mount -o remount,discard /

mkdir -p /mnt/{source,output,tmp}
mount -t 9p /dev/source -o version=9p2000.L,trans=virtio,access=any /mnt/source
mount -t 9p /dev/output -o version=9p2000.L,trans=virtio,access=any /mnt/output
mount -t tmpfs tmpfs /mnt/tmp
mkdir -p /mnt/tmp/{upper,work}
mkdir -p "${REPO}"
mount -t overlay overlay -o lowerdir=/mnt/source,upperdir=/mnt/tmp/upper,workdir=/mnt/tmp/work "${REPO}"

mount -t 9p /dev/binpkgs -o version=9p2000.L,trans=virtio,access=any "${REPO}/vm/binpkgs"

sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
apt update
apt install -y docker.io qemu-utils
BUILD_LOGO='$BUILD_LOGO' "${REPO}/vm/build.sh"
cp "${REPO}/vm/ishoal.ova" /mnt/output/ishoal.ova
cp "${REPO}/vm/ishoal-update.tgz" /mnt/output/ishoal-update.tgz
sync
INNEREOF

sudo bash \$SCRIPT
EOF

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i sshkey ubuntu@127.0.0.1 -p "${PORT}" sudo poweroff || true
wait "$QEMU_PID"
RUNNING=false

cp output/ishoal.ova "${REPO}/vm/ishoal.ova"
cp output/ishoal-update.tgz "${REPO}/vm/ishoal-update.tgz"

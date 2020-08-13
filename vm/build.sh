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

truncate -s $((256 * 1048576)) disk.img
fdisk disk.img << EOF
o
n
p
1
2048
65535
n
p
2
65536
524287
a
1
w
EOF

BOOT="$(sudo losetup --offset $(( 2048 * 512 )) --sizelimit $(( 63488 * 512 )) --show --find disk.img)"
ROOT="$(sudo losetup --offset $(( 65536 * 512 )) --sizelimit $(( 458752 * 512 )) --show --find disk.img)"

sudo mkfs.vfat "$BOOT"
sudo mkfs.btrfs "$ROOT"

sudo docker run -v $PWD:$PWD -w $PWD --tmpfs /var/tmp/portage:exec --tmpfs /var/cache/distfiles --tmpfs /var/db/repos --cap-add=SYS_PTRACE --rm -i gentoo/stage3-x86 << 'EOF'
set -ex

emerge-webrsync

emerge -v -n syslinux

syslinux -t $(( 2048 * 512 )) -i disk.img
dd bs=440 count=1 conv=notrunc if=/usr/share/syslinux/mbr.bin of=disk.img
EOF

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

sudo docker run -v $REPO:$REPO -e REPO="${REPO}" -v $PWD:$PWD -w $PWD --tmpfs /var/tmp/portage:exec --tmpfs /var/cache/distfiles --tmpfs /var/db/repos --cap-add=SYS_PTRACE --rm -i gentoo/stage3-x86 << 'EOF'
set -ex

LINUX_VER=5.8.1
PY_VER=3.8

emerge-webrsync

export LLVM_TARGETS=BPF ACCEPT_KEYWORDS='~x86'
emerge -v -o sys-devel/llvm:10
MAKEOPTS="-j$(( $(nproc) < 4 ? $(nproc) : 4 ))" emerge -v -n sys-devel/llvm:10 sys-devel/clang:10
unset LLVM_TARGETS ACCEPT_KEYWORDS

emerge -v -o gentoo-sources

source /etc/profile

wget "https://cdn.kernel.org/pub/linux/kernel/v${LINUX_VER%.*.*}.x/linux-${LINUX_VER}.tar.xz"
tar xf "linux-${LINUX_VER}.tar.xz"
mv "linux-${LINUX_VER}" kernel

pushd kernel
./scripts/kconfig/merge_config.sh ./arch/x86/configs/i386_defconfig "${REPO}/vm/kconfig"
popd

make -C kernel -j"$(nproc)"

make -C kernel/tools/bpf/bpftool/

emerge -v -n "dev-lang/python:${PY_VER}" dev-util/dialog
ACCEPT_KEYWORDS='~x86' emerge -v dev-libs/libbpf

"python${PY_VER}" -m ensurepip

rm "${REPO}/src/"*.d || true
make -B -C "${REPO}/src/" PYTHON="python${PY_VER}" BPFTOOL="$(realpath kernel/tools/bpf/bpftool/bpftool)"

export USE='-* make-symlinks unicode ssl ncurses readline'
emerge --root rootfs -v sys-apps/baselayout
emerge --root rootfs -v sys-apps/busybox
emerge --root rootfs -v "dev-lang/python:${PY_VER}" dev-util/dialog
emerge --root rootfs -v sys-process/htop
ACCEPT_KEYWORDS='~x86' emerge --root rootfs -v dev-libs/libbpf
unset USE

GCC_PATH="$(gcc -print-search-dirs | grep install | cut -d\  -f2)"
mkdir -p rootfs/"${GCC_PATH}"
cp -a "${GCC_PATH}"/libgcc_s.so* rootfs/"${GCC_PATH}"
echo "${GCC_PATH}" > rootfs/etc/ld.so.conf
ldconfig -C rootfs/etc/ld.so.cache -f rootfs/etc/ld.so.conf

find rootfs/usr/share/i18n/locales/ -mindepth 1 -maxdepth 1 ! -name 'en_US' ! -name 'en_GB' ! -name 'C' ! -name 'i18n*' ! -name 'iso*' ! -name 'translit*' -delete
find rootfs/usr/share/i18n/charmaps/ -mindepth 1 -maxdepth 1 -name '*.gz' ! -name 'UTF*' ! -name 'LATIN*' -delete
find rootfs/usr/lib/gconv/ -mindepth 1 -maxdepth 1 -name '*.so' ! -name 'UTF*' ! -name 'LATIN*' ! -name 'UNICODE*' -delete
find rootfs/usr/share/locale/ -mindepth 1 -maxdepth 1 -type d ! -name 'en_US' ! -name 'en_GB' ! -name 'C' -exec rm -r {} \;
find rootfs/usr/share/terminfo/ -mindepth 2 -maxdepth 2 ! -name 'ansi*' ! -name 'linux*' ! -name 'vt*' ! -name 'xterm*' ! -name 'screen*' ! -name 'gnome*' -delete
find rootfs/usr/share/terminfo/ -empty -type d -delete

rm -r rootfs/usr/share/doc/
rm -r rootfs/usr/share/man/
rm -r rootfs/usr/share/info/
rm -r rootfs/usr/include/
rm -r rootfs/usr/share/misc/magic*
rm -r rootfs/usr/lib/python*/test
rm -r rootfs/usr/lib/python*/unittest
find rootfs/usr/lib/python*/ -name '__pycache__' -prune -exec rm -r {} \;

rm -r rootfs/var/db/pkg/
rm -r rootfs/var/cache/edb/
rm -r rootfs/etc/portage/

rm -r rootfs/lib/gentoo/ || true
rm -r rootfs/var/lib/gentoo/ || true
rm -r rootfs/var/lib/portage/ || true

rm -r rootfs/usr/share/gdb/ || true
rm -r rootfs/usr/share/baselayout/ || true

mkdir -p rootfs/{boot,dev,proc,root,run,sys}

mknod -m 622 rootfs/dev/console c 5 1
mknod -m 666 rootfs/dev/null c 1 3
mknod -m 666 rootfs/dev/zero c 1 5
mknod -m 666 rootfs/dev/ptmx c 5 2
mknod -m 666 rootfs/dev/tty c 5 0
mknod -m 444 rootfs/dev/random c 1 8
mknod -m 444 rootfs/dev/urandom c 1 9

ln -s /proc/self/fd rootfs/dev/fd
ln -s /proc/self/fd/0 rootfs/dev/stdin
ln -s /proc/self/fd/1 rootfs/dev/stdout
ln -s /proc/self/fd/2 rootfs/dev/stderr
mkdir -m 0755 rootfs/dev/shm
mkdir rootfs/dev/pts

mkdir -p rootfs/var/log
ln -s /proc/self/mounts rootfs/etc/mtab
touch rootfs/etc/fstab

echo ishoal > rootfs/etc/hostname
echo 'nameserver 8.8.8.8' > rootfs/etc/resolv.conf

mkdir -p rootfs/etc/init.d/

cat > rootfs/etc/init.d/rcS << 'INNEREOF'
#! /bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -n -t proc -o nosuid,noexec,nodev proc /proc
mount -n -t tmpfs -o nosuid,nodev tmpfs /run
mount -n -t sysfs -o nosuid,noexec,nodev sys /sys
mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp

mount -n -t debugfs debugfs /sys/kernel/debug

mkdir -p /dev/pts
mount -n -t devpts -o gid=tty,mode=620,noexec,nosuid devpts /dev/pts
mkdir -p /dev/shm
mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm

mount -t bpf bpffs /sys/fs/bpf

mdev -s
mdev -d

mount -o remount,rw /

hostname ishoal

ip link set dev lo up
ip link set dev eth0 up
udhcpc -i eth0 -p /run/udhcpc -s /usr/share/udhcpc/default.script -q -n -f

ping -w 5 -c 1 8.8.8.8

dmesg -n 1
INNEREOF
chmod a+x rootfs/etc/init.d/rcS

cat > rootfs/root/ishoal-wrapper << 'INNEREOF'
#! /bin/sh
while true; do
  echo 'Booting iShoal ...'
  /root/ishoal eth0
  EXITCODE=$?

  if [ $EXITCODE -eq 2 ]; then
    sync
    clear
    poweroff
    echo 'Waiting for system shutdown.'
    sleep 20
  elif [ $EXITCODE -eq 3 ]; then
    sync
    clear
    reboot
    echo 'Waiting for system reboot.'
    sleep 20
  elif [ $EXITCODE -ne 0 ]; then
    echo 'IShoal failed, entering shell. Please type 'exit' to exit the shell.'
    /bin/sh
  fi
done
INNEREOF
chmod a+x rootfs/root/ishoal-wrapper

cat > rootfs/etc/inittab << 'INNEREOF'
::sysinit:/etc/init.d/rcS
tty1::respawn:/root/ishoal-wrapper
tty2::respawn:-/bin/sh
::restart:/sbin/init
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
INNEREOF

cp "${REPO}/src/ishoal" rootfs/root/ishoal
chmod a+x rootfs/root/ishoal

cp kernel/arch/x86/boot/bzImage rootfs/boot/LINUX
cat > rootfs/boot/syslinux.cfg << INNEREOF
default LINUX
INNEREOF
EOF

do_cleanup_mnt
MOUNTED=false

qemu-img convert disk.img -O vmdk -o subformat=streamOptimized ishoal-disk001.vmdk
cp "${DIR}/ishoal.ovf" ishoal.ovf

echo "SHA1 (ishoal-disk001.vmdk) = $(sha1sum ishoal-disk001.vmdk | cut -d\  -f 1 )" >> ishoal.mf
echo "SHA1 (ishoal.ovf) = $(sha1sum ishoal.ovf | cut -d\  -f 1 )" >> ishoal.mf

tar cvf ishoal.ova ishoal.ovf ishoal-disk001.vmdk ishoal.mf

cp -a ishoal.ova "${DIR}/ishoal.ova"

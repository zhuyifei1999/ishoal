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

LINUX_PV=5.7.9
wget "https://cdn.kernel.org/pub/linux/kernel/v${LINUX_PV%.*.*}.x/linux-${LINUX_PV}.tar.xz"
tar xf "linux-${LINUX_PV}.tar.xz"
mv "linux-${LINUX_PV}" kernel

pushd kernel
./scripts/kconfig/merge_config.sh ./arch/x86/configs/x86_64_defconfig "${DIR}/kconfig"
make -j"$(nproc)"
popd


mkdir rootfs

truncate -s $((256 * 1048576)) disk.img
fdisk disk.img << EOF
g
n
1
2048
65535
n
2
65536
524254
w
EOF

BOOT="$(sudo losetup --offset $(( 2048 * 512 )) --sizelimit $(( 63488 * 512 )) --show --find disk.img)"
ROOT="$(sudo losetup --offset $(( 65536 * 512 )) --sizelimit $(( 458719 * 512 )) --show --find disk.img)"

sudo mkfs.fat "$BOOT"
sudo mkfs.btrfs "$ROOT"

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

sudo docker run -v $PWD:$PWD -w $PWD --tmpfs /var/tmp/portage:exec --tmpfs /var/cache/distfiles --tmpfs /var/db/repos --cap-add=SYS_PTRACE --rm -i gentoo/stage3-amd64-nomultilib << 'EOF'
set -ex
emerge-webrsync

export USE='-* make-symlinks unicode ssl ncurses readline'
emerge --quiet-build --root rootfs -v sys-apps/baselayout
emerge --quiet-build --root rootfs -v sys-apps/busybox
emerge --quiet-build --root rootfs -v dev-lang/python dev-util/dialog net-libs/miniupnpc
emerge --quiet-build --root rootfs -v sys-process/htop
ACCEPT_KEYWORDS='~amd64' emerge --quiet-build --root rootfs -v dev-libs/libbpf

GCC_PATH="$(gcc -print-search-dirs | grep install | cut -d\  -f2)"
mkdir -p rootfs/"${GCC_PATH}"
cp -a "${GCC_PATH}"/libgcc_s.so* rootfs/"${GCC_PATH}"
echo "${GCC_PATH}" > rootfs/etc/ld.so.conf
ldconfig -C rootfs/etc/ld.so.cache -f rootfs/etc/ld.so.conf

find rootfs/usr/share/i18n/locales/ -mindepth 1 -maxdepth 1 ! -name 'en_US' ! -name 'en_GB' ! -name 'C' ! -name 'i18n*' ! -name 'iso*' ! -name 'translit*' -delete
find rootfs/usr/share/i18n/charmaps/ -mindepth 1 -maxdepth 1 -name '*.gz' ! -name 'UTF*' ! -name 'LATIN*' -delete
find rootfs/usr/lib64/gconv/ -mindepth 1 -maxdepth 1 -name '*.so' ! -name 'UTF*' ! -name 'LATIN*' ! -name 'UNICODE*' -delete
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
EOF

sudo cp "${DIR}/../src/ishoal" rootfs/root/ishoal
sudo chmod a+x rootfs/root/ishoal

sudo mkdir -p rootfs/boot/EFI/Boot/
sudo cp kernel/arch/x86/boot/bzImage rootfs/boot/linux.efi
sudo cp "${DIR}/efi_fb_res/efi_fb_res.efi" rootfs/boot/EFI/Boot/bootx64.efi

do_cleanup_mnt
MOUNTED=false

cp -a disk.img "${DIR}/disk.img"

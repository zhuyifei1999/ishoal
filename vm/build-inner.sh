#!/bin/bash

set -ex

LINUX_VER=5.11.3
PY_VER=3.9
EDKII_VER=202102

emerge-webrsync

shopt -s expand_aliases
alias emerge='emerge --color=y --quiet-build'

export FEATURES='buildpkg'

# https://bugs.gentoo.org/753935
# https://github.com/gentoo/gentoo/blob/master/profiles/default/linux/musl/package.use.mask
# https://github.com/gentoo/gentoo/blob/master/profiles/features/musl/package.use.mask
mkdir -p /etc/portage/profile
cat > /etc/portage/profile/package.use.mask << 'EOF'
sys-devel/clang-runtime sanitize
EOF

emerge -vuk sys-apps/portage
emerge -vuDNk --with-bdeps=y @world
emerge -c

emerge -vuk app-portage/layman
layman -f
layman -a musl

# For bpftool
mkdir -p /etc/portage/patches/sys-libs/musl
ln -s "${REPO}/vm/musl-nftw.patch" /etc/portage/patches/sys-libs/musl
ln -s "${REPO}/vm/musl-821083ac7b54eaa040d5a8ddc67c6206a175e0ca.patch" /etc/portage/patches/sys-libs/musl
emerge -vk sys-libs/musl

emerge -vnk app-portage/portage-utils

source /etc/profile

emerge -vnk app-portage/repoman

mkdir -p /var/db/repos/localrepo/{metadata,profiles}
chown -R portage:portage /var/db/repos/localrepo
echo localrepo > /var/db/repos/localrepo/profiles/repo_name

cat > /var/db/repos/localrepo/metadata/layout.conf << 'EOF'
masters = gentoo
auto-sync = false
EOF

mkdir -p /etc/portage/repos.conf/
cat > /etc/portage/repos.conf/localrepo.conf << 'EOF'
[localrepo]
location = /var/db/repos/localrepo
EOF

mkdir -p /var/db/repos/localrepo/sys-apps/bpftool/
cp "${REPO}/vm/bpftool.ebuild" "/var/db/repos/localrepo/sys-apps/bpftool/bpftool-${LINUX_VER}.ebuild"

mkdir -p /var/db/repos/localrepo/sys-boot/edk2/files/
cp "${REPO}/vm/edk2.ebuild" "/var/db/repos/localrepo/sys-boot/edk2/edk2-${EDKII_VER}.ebuild"
cp "${REPO}/vm/edk2-workspace.template" /var/db/repos/localrepo/sys-boot/edk2/files/

chown -R portage:portage /var/db/repos/localrepo

export FETCHCOMMAND='wget -q -c -t 3 -T 60 --passive-ftp -O "${DISTDIR}/${FILE}" "${URI}"'
pushd /var/db/repos/localrepo/sys-apps/bpftool/
repoman manifest -q
popd

pushd /var/db/repos/localrepo/sys-boot/edk2/
repoman manifest -q
popd
unset FETCHCOMMAND

export LLVM_TARGETS=BPF
emerge -vok --with-bdeps=y sys-devel/llvm
MAKEOPTS="-j$(( $(nproc) < 4 ? $(nproc) : 4 ))" emerge -vnk sys-devel/llvm sys-devel/clang
unset LLVM_TARGETS

emerge -vok gentoo-sources

source /etc/profile

# wget -nv "https://cdn.kernel.org/pub/linux/kernel/v${LINUX_VER%.*.*}.x/linux-${LINUX_VER}.tar.xz"
cp "/var/cache/distfiles/linux-${LINUX_VER}.tar.xz" .
tar xf "linux-${LINUX_VER}.tar.xz"
mv "linux-${LINUX_VER}" kernel

pushd kernel
./scripts/kconfig/merge_config.sh ./arch/x86/configs/x86_64_defconfig "${REPO}/vm/kconfig_s1"
./scripts/kconfig/merge_config.sh .config "${REPO}/vm/kconfig_s2"
popd

emerge -vnk dev-python/pillow

pushd "${REPO}/vm/ohlawdhecomin"
python generate_data.py
popd

ln -s "${REPO}/vm/ohlawdhecomin" kernel/drivers/firmware/efi
echo 'obj-$(CONFIG_EFI_EARLYCON) += ohlawdhecomin/ohlawdhecomin.o' >> kernel/drivers/firmware/efi/Makefile

make -C kernel -j"$(nproc)"

emerge -vnk "dev-lang/python:${PY_VER}" dev-util/dialog dev-libs/userspace-rcu

# https://github.com/netdata/kernel-collector/issues/23
patch /usr/include/asm/byteorder.h << 'EOF'
--- /usr/include/asm/byteorder.h
+++ /usr/include/asm/byteorder.h
@@ -2,6 +2,7 @@
 #ifndef _ASM_X86_BYTEORDER_H
 #define _ASM_X86_BYTEORDER_H

+#include <linux/stddef.h>
 #include <linux/byteorder/little_endian.h>

 #endif /* _ASM_X86_BYTEORDER_H */
EOF

ACCEPT_KEYWORDS='~amd64' emerge -vnk dev-libs/libbpf sys-apps/bpftool

"python${PY_VER}" -m ensurepip

bash "${REPO}/src/extern/get.sh"
make -B -C "${REPO}/src/" PYTHON="python${PY_VER}" CFLAGS='-Os -pipe -flto -fno-semantic-interposition -Wall' CLANGFLAGS='-fno-lto -g -D__x86_64__' DO_STRIP=1

ACCEPT_KEYWORDS='~amd64' emerge -vnk sys-boot/edk2
bash "${REPO}/vm/IShoalPkg/build.sh"

qpkg -c

unset FEATURES

# Busybox will invoke its own commands internally, and its retty good, so why bother
mkdir -p /etc/portage/profile/
cat > /etc/portage/profile/package.provided << 'EOF'
sys-apps/coreutils-9999
sys-apps/util-linux-9999
sys-apps/sed-9999
sys-apps/grep-9999
sys-apps/gentoo-functions-9999
sys-apps/debianutils-9999
sys-apps/file-9999
app-arch/gzip-9999
app-arch/bzip2-9999
app-arch/xz-utils-9999
EOF

cat > /etc/portage/bashrc << EOF
if [ "\${EBUILD_PHASE}" == "preinst" ]; then
  find "\$ED"/usr/share/terminfo/ -mindepth 2 -maxdepth 2 ! -name 'ansi*' ! -name 'linux*' -delete
  find "\$ED"/usr/share/terminfo/ -empty -type d -delete
  find "\$ED"/usr/lib/python*/ -name '__pycache__' -prune -exec rm -r {} \;

  if [ -d "\$ED"/usr/lib/python${PY_VER}/ ]; then
    python "${REPO}"/src/py-trimmer.py "\$ED"/usr/lib/python${PY_VER}/
  fi

  rm -r "\$ED"/usr/share/doc/
  rm -r "\$ED"/usr/share/man/
  rm -r "\$ED"/usr/share/info/
  rm -r "\$ED"/usr/include/

  rm -r "\$ED"/usr/lib/python*/test
  rm -r "\$ED"/usr/lib/python*/unittest
  rm -r "\$ED"/usr/lib/python*/ensurepip
  find "\$ED"/usr/lib/python*/ -name 'test' -prune -exec rm -r {} \;
  find "\$ED"/usr/lib/python*/ -name 'tests' -prune -exec rm -r {} \;

  find "\$ED"/usr/lib{,64}/ -name '*.a' -delete
  find "\$ED"/usr/lib{,64}/ -name '*.o' -delete
  find "\$ED"/usr/lib{,64}/ -name '*.la' -delete
  find "\$ED"/usr/lib{,64}/ -name '*.pc' -delete
fi
EOF

export USE='-* make-symlinks native-symlinks unicode ssl ncurses readline bindist'
emerge --root rootfs -v sys-apps/baselayout
emerge --root rootfs -v sys-libs/musl

export CFLAGS='-Os -pipe -flto -fipa-pta -fno-semantic-interposition -fdevirtualize-at-ltrans -fuse-linker-plugin'
export LDFLAGS='-Wl,-O1 -Wl,--as-needed -Wl,--hash-style=gnu'
emerge --root rootfs -v sys-apps/busybox
emerge --root rootfs -v "dev-lang/python:${PY_VER}" dev-util/dialog dev-libs/userspace-rcu
emerge --root rootfs -v sys-process/htop sys-process/lsof dev-util/strace
unset CFLAGS LDFLAGS

ACCEPT_KEYWORDS='~amd64' emerge --root rootfs -v dev-libs/libbpf sys-apps/bpftool
unset USE

make -C kernel -j"$(nproc)" modules_install INSTALL_MOD_PATH="$(realpath rootfs)"

GCC_PATH="$(gcc -print-search-dirs | grep install | cut -d\  -f2)"
mkdir -p rootfs/"${GCC_PATH}"
cp -a "${GCC_PATH}"/libgcc_s.so* rootfs/"${GCC_PATH}"
echo "${GCC_PATH}" >> rootfs/etc/ld-musl-x86_64.path
cat >> rootfs/etc/ld-musl-x86_64.path << 'EOF'
/lib
/usr/lib
/usr/local/lib
EOF

set +e

rm -r rootfs/var/db/pkg/
rm -r rootfs/var/cache/edb/
rm -r rootfs/etc/portage/

rm -r rootfs/lib/gentoo/
rm -r rootfs/var/lib/gentoo/
rm -r rootfs/var/lib/portage/

rm -r rootfs/usr/share/gdb/
rm -r rootfs/usr/share/baselayout/

set -e

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

cat > rootfs/etc/init.d/rcS << 'EOF'
#! /bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -n -t proc -o nosuid,noexec,nodev proc /proc
mount -n -t tmpfs -o nosuid,nodev tmpfs /run
mount -n -t sysfs -o nosuid,noexec,nodev sys /sys
mount -n -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp

mount -n -t debugfs debugfs /sys/kernel/debug

mkdir -p /dev/pts
mount -n -t devpts -o gid=5,mode=620,noexec,nosuid devpts /dev/pts
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
EOF
chmod a+x rootfs/etc/init.d/rcS

cat > rootfs/root/ishoal-wrapper << 'EOF'
#! /bin/sh
while true; do
  echo 'Starting IShoal ...'
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
EOF
chmod a+x rootfs/root/ishoal-wrapper

cat > rootfs/etc/inittab << 'EOF'
::sysinit:/etc/init.d/rcS
tty1::respawn:/root/ishoal-wrapper
tty2::respawn:-/bin/sh
::restart:/sbin/init
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -n -r
EOF

cp "${REPO}/src/ishoal" rootfs/root/ishoal
chmod a+x rootfs/root/ishoal

mkdir -p rootfs/boot/EFI/Boot/
cp kernel/arch/x86/boot/bzImage rootfs/boot/linux.efi
cp "${REPO}/vm/IShoalPkg/IShoal.efi" rootfs/boot/EFI/Boot/bootx64.efi

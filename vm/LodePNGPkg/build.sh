#!/bin/bash

set -e

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

source edk2-workspace edk2-workspace

cd edk2-workspace
ln -s /usr/lib/edk2/MdePkg .
ln -s "${DIR}" LodePNGPkg

build -b RELEASE -p LodePNGPkg/LodePNGPkg.dsc -s

cp -a Build/LodePNGPkg/RELEASE_GCC5/X64/LodePNGDecode.efi "${DIR}"

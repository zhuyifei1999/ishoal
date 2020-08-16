#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR"

get_file() {
  mkdir -p "$(dirname "$1")"
  wget -O "$1" -- "$2"
}

get_file plthook/plthook.h https://github.com/kubo/plthook/raw/master/plthook.h
get_file plthook/plthook_elf.c https://github.com/kubo/plthook/raw/master/plthook_elf.c

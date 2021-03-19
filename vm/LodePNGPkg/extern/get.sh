#!/bin/bash

set -ex

# https://stackoverflow.com/a/246128
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd "$DIR"

get_file() {
  mkdir -p "$(dirname "$1")"
  wget -O "$1" -- "$2"
}

get_file lodepng/lodepng.h https://github.com/lvandeve/lodepng/raw/master/lodepng.h
get_file lodepng/lodepng.c https://github.com/lvandeve/lodepng/raw/master/lodepng.cpp

# iShoal

Splatoon 2 Internet Shoal, peer to peer, without the lag.

## Usage

Same as iShoal v1.2.0. Download `ishoal.ova` from https://ishoal.ink/dist/ishoal.ova.
Import the `ishoal.ova` into [VirtualBox](https://www.virtualbox.org/).
The rest is to be documented...

This is not fundamentally restricted to Shoal. It works for any switch LAN play,
including other games, after the switch IP address and MAC address are detected
via Shoal LAN mode or entered manually.

## Development

### Build

Requirements: bash, git, qemu, ssh, and wget. Up to 8G memory and 10G disk
space will be used for the build process.

Execute `vm/build-wrapper.sh` in bash. If successful. will produce an
`ishoal.ova` under the `vm` directory.

### Contributing

Issues and pull requests are welcome.

This is a project thanks to the help from the
[Salmon Run Discord Server](https://discord.gg/EY3JZqk). Credits to Ionizer for
the idea and creating the original iShoal based on client-server VPN. A lot of
wheels has been reinvented in this project.

## License

Copyright (C) 2020 YiFei Zhu

The project as a whole is under GNU General Public License Version 2;
individual files may have additional license noted in the files.

This program is free software; you can redistribute it and/or modify
it under the terms of version 2 of the GNU General Public License as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

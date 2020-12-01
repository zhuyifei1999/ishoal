EAPI=7

inherit toolchain-funcs linux-info

DESCRIPTION="bpftool"
HOMEPAGE="https://kernel.org/"
SRC_URI="https://cdn.kernel.org/pub/linux/kernel/v$(ver_cut 1).x/linux-${PV}.tar.xz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+caps"

DEPEND="dev-libs/libbpf
	virtual/libelf
	sys-libs/zlib
	caps? ( sys-libs/libcap )"
RDEPEND="${DEPEND}"
BDEPEND=""

S="${WORKDIR}/linux-${PV}/tools/bpf/bpftool/"

KBUILD_OUTPUT=
ARCH=$(tc-arch-kernel)

src_compile() {
	local myconf=( )

	use caps || myconf+=( feature-libcap=0 )

	emake CC="$(tc-getCC)" "${myconf[@]}"
}

src_install() {
	emake prefix=/usr DESTDIR="${D}" install
}
